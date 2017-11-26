module Network.PeerDiscovery.Communication
  ( module Network.PeerDiscovery.Communication.Types
  , sendRequest
  , handleRequest
  , handleResponse
  ) where

import Control.Concurrent
import Control.Monad
import Data.Typeable
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Communication.Types
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Util

class Typeable (ResponseType r) => IsRequest r where
  type ResponseType r :: *
  toRequest :: r -> Request

instance IsRequest FindNode where
  type ResponseType FindNode = ReturnNodes
  toRequest = FindNodeR

instance IsRequest Ping where
  type ResponseType Ping = Pong
  toRequest = PingR

instance IsRequest RequestAuth where
  type ResponseType RequestAuth = AuthProof
  toRequest = RequestAuthR

-- | Asynchronously send a request to a peer and perform specific actions on
-- failure or response arrival. Note that there are multiple things that can go
-- wrong:
--
-- 1) We didn't get the response from the recipient in time.
--
-- 2) We got the response, but it couldn't be parsed.
--
-- 3) We got the response, but its RpcId was different than expected.
--
-- 4) We got the response, but its source address was different than expected.
--
-- 5) We got the response, but its type was different than expected.
--
-- We log each of these cases, but on the application level we aren't really
-- interested in what exactly went wrong, only the fact that communication with
-- a given peer is not reliable, hence onFailure action doesn't take any
-- parameter signifying the type of failure.
sendRequest
  :: (IsRequest req, Show req)
  => PeerDiscovery
  -> req                         -- ^ Request to be sent
  -> Peer                        -- ^ Recipient
  -> IO ()                       -- ^ Action to perform on failure
  -> (ResponseType req -> IO ()) -- ^ Action to perform on success
  -> IO ()
sendRequest pd req peer onFailure onSuccess = do
  rpcId <- randomRpcId
  let signal = Request rpcId (toRequest req)
  modifyMVar_ (pdResponseHandlers pd) $ \handlers -> do
    sendSignal (pdSocket pd) signal peer
    tid <- forkIO (timeoutHandler rpcId)
    let handler = ResponseHandler { rhRecipient        = peer
                                  , rhTimeoutHandlerId = tid
                                  , rhOnFailure        = onFailure
                                  , rhHandler          = onSuccess
                                  }
    return $! M.insert rpcId handler handlers
  where
    timeoutHandler rpcId = do
      threadDelay . configResponseTimeout $ pdConfig pd
      myTid <- myThreadId
      -- We need to remove response handler from the map before running timeout
      -- action as it might happen that dispatcher already pulled it from the
      -- map, but didn't kill this thread yet.
      ok <- modifyMVarP (pdResponseHandlers pd) $ \handlers ->
        case M.lookup rpcId handlers of
          Just (ResponseHandler _ tid _ _)
            -- Theoretically (with miniscule probability) it's possible that a
            -- response handler for a different request with the same rpcId was
            -- already scheduled, so as a paranoia check let's also compare
            -- thread ids.
            | tid == myTid -> (M.delete rpcId handlers, True)
          _                -> (handlers, False)
      when ok $ do
        putStrLn $ "Request " ++ show req ++ " with " ++ show rpcId ++ " timed out"
        onFailure

----------------------------------------

-- | Handle appropriate 'Request'.
handleRequest :: PeerDiscovery -> Peer -> RpcId -> Request -> IO ()
handleRequest PeerDiscovery{..} peer rpcId rq = case rq of
  FindNodeR (FindNode peerId mport targetId) -> do
    peers <- modifyMVarP pdRoutingTable $ \oldTable ->
      let mnode = mport <&> \port -> Node { nodeId   = peerId
                                          , nodePeer = peer { peerPort = port }
                                          }
          -- If we got a port number, we assume that peer is globally reachable
          -- under its IP address and received port number, so we insert it into
          -- our routing table. In case it lied it's not a big deal, it will be
          -- evicted soon enough.
          table = maybe oldTable (\p -> insertPeer pdConfig p oldTable) mnode
      in (table, findClosest (configK pdConfig) targetId table)
    sendSignal pdSocket (Response rpcId $ ReturnNodesR (ReturnNodes peers)) peer
  PingR Ping -> sendSignal pdSocket (Response rpcId (PongR Pong)) peer
  RequestAuthR (RequestAuth nonce) -> do
    -- We got authentication request. It usually happens when our ip or port has
    -- changed, the sender has the old entry in his routing table and wants to
    -- update it, but needs a confirmation that we are not trying to eclipse an
    -- existing node. He sends us nonce, which we sign using our private key,
    -- then send a response containing our public key and the signature we just
    -- created. The sender can verify that the public key belongs to us as he
    -- has our id (which is its hash) and that we possess the corresponding
    -- private key by checking that signature is correct.
    let signature = C.sign pdSecretKey pdPublicKey nonce
        response  = AuthProofR (AuthProof pdPublicKey signature)
    sendSignal pdSocket (Response rpcId response) peer

-- | Handle 'Response' signals by looking up and running appropriate handler
-- that was registered when a 'Request' was sent.
handleResponse :: ResponseHandlers -> Peer -> RpcId -> Response -> IO ()
handleResponse responseHandlers peer rpcId rsp = retrieveHandler >>= \case
  Nothing      -> putStrLn $ "handleResponse: no handler for " ++ show rpcId
  Just handler -> case rsp of
    ReturnNodesR returnPeers -> runHandler handler returnPeers
    PongR pong               -> runHandler handler pong
    AuthProofR authProof     -> runHandler handler authProof
  where
    retrieveHandler = modifyMVarP responseHandlers $ \handlers ->
      case M.lookup rpcId handlers of
        Just handler -> (M.delete rpcId handlers, Just handler)
        Nothing      -> (handlers, Nothing)

    runHandler :: forall a. Typeable a => ResponseHandler -> a -> IO ()
    runHandler ResponseHandler{..} a = do
      killThread rhTimeoutHandlerId
      if peer /= rhRecipient
        then do
           putStrLn $ "handleResponse: response recipient " ++ show rhRecipient
                   ++ " doesn't match source of the response: " ++ show peer
           rhOnFailure
        else case rhHandler <$> cast a of
          Just run -> run
          Nothing  -> do
            putStrLn $ "handleResponse: expected response of type "
                    ++ show (typeOf (arg rhHandler)) ++ ", but got "
                    ++ show (typeOf a) ++ " for " ++ show rpcId
            rhOnFailure
      where
        arg :: (r -> IO ()) -> r
        arg _ = error "handleResponse.arg"
