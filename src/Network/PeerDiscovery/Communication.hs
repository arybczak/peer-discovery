module Network.PeerDiscovery.Communication
  ( Signal(..)
  , sendRequest
  , handleRequest
  , handleResponse
  ) where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import Codec.Serialise
import Control.Concurrent
import Control.Monad
import Data.Monoid
import Data.Typeable
import Network.Socket hiding (recvFrom, sendTo)
import Network.Socket.ByteString
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Util

data Signal = Request  !RpcId                           !Request
            | Response !RpcId !C.PublicKey !C.Signature !Response
  deriving (Eq, Show)

instance Serialise Signal where
  encode = \case
    Request  rpcId rq  -> encodeListLen 3
                       <> encodeWord 0
                       <> encode rpcId
                       <> encode rq
    Response rpcId pkey signature rsp -> encodeListLen 5
                                      <> encodeWord 1
                                      <> encode rpcId
                                      <> encodePublicKey pkey
                                      <> encodeSignature signature
                                      <> encode rsp
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> do
        matchSize 3 "decode(Signal).Request" len
        Request <$> decode <*> decode
      1 -> do
        let label = "decode(Signal).Response"
        matchSize 5 label len
        Response <$> decode
                 <*> decodePublicKey label
                 <*> decodeSignature label
                 <*> decode
      n -> fail $ "decode(Signal): invalid tag: " ++ show n

sendSignal :: Socket -> Signal -> Peer -> IO ()
sendSignal sock signal Peer{..} = do
  void $ sendTo sock (serialise' signal) (SockAddrInet peerPort peerAddress)

----------------------------------------

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
-- 5) We got the response, but verification of its signature failed.
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
  -> Node                        -- ^ Recipient
  -> IO ()                       -- ^ Action to perform on failure
  -> (ResponseType req -> IO ()) -- ^ Action to perform on success
  -> IO ()
sendRequest pd reqType peer onFailure onSuccess = do
  rpcId <- randomRpcId
  let request = toRequest reqType
      signal  = Request rpcId request
  modifyMVar_ (pdResponseHandlers pd) $ \handlers -> do
    sendSignal (pdSocket pd) signal (nodePeer peer)
    tid <- forkIO (timeoutHandler rpcId)
    let handler = ResponseHandler { rhRequest          = request
                                  , rhRecipient        = peer
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
          Just ResponseHandler{..}
            -- Paranoia check. Make sure this is the correct response handler.
            | rhTimeoutHandlerId == myTid -> (M.delete rpcId handlers, True)
          _                               -> (handlers, False)
      when ok $ do
        putStrLn $ "Request " ++ show reqType ++ " with " ++ show rpcId ++ " timed out"
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
          table =
            -- If it comes to nodes who send us requests, we only insert them
            -- into the table if the highest bit of their id is different than
            -- ours. This way an adversary:
            --
            -- 1) Can't directly influence our neighbourhood by flooding us with
            -- reqeusts from nodes that are close to us.
            --
            -- 2) Will have a hard time getting a large influence in our routing
            -- table because the branch representing different highest bit
            -- accounts for half of the network, so its buckets will most likely
            -- be full.
            if peerId `distance` rtId oldTable < 2^(peerIdBitSize - 1)
            then maybe oldTable (\node -> clearTimeoutPeer node oldTable)    mnode
            else maybe oldTable (\node -> insertPeer pdConfig node oldTable) mnode
      in (table, findClosest (configK pdConfig) targetId table)
    sendResponse $ ReturnNodesR (ReturnNodes peers)
  PingR Ping -> sendResponse $ PongR Pong
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
    sendResponse response
  where
    sendResponse rsp =
      let signature = C.sign pdSecretKey pdPublicKey (toMessage rpcId rq rsp)
      in sendSignal pdSocket (Response rpcId pdPublicKey signature rsp) peer

-- | Handle 'Response' signals by looking up and running appropriate handler
-- that was registered when a 'Request' was sent.
handleResponse
  :: ResponseHandlers
  -> Peer
  -> RpcId
  -> C.PublicKey
  -> C.Signature
  -> Response
  -> IO ()
handleResponse responseHandlers peer rpcId pkey signature rsp = do
  retrieveHandler >>= \case
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
      if | node /= rhRecipient -> do
             putStrLn $ "handleResponse: response recipient " ++ show rhRecipient
                     ++ " doesn't match source of the response: " ++ show node
             rhOnFailure
         | not $ C.verify pkey (toMessage rpcId rhRequest rsp) signature -> do
             putStrLn $ "handleResponse: response verification failed"
             rhOnFailure
         | otherwise -> case rhHandler <$> cast a of
             Just run -> run
             Nothing  -> do
               putStrLn $ "handleResponse: expected response of type "
                        ++ show (typeOf (arg rhHandler)) ++ ", but got "
                        ++ show (typeOf a) ++ " for " ++ show rpcId
               rhOnFailure
      where
        node = Node { nodeId   = mkPeerId pkey
                    , nodePeer = peer
                    }

        arg :: (r -> IO ()) -> r
        arg _ = error "handleResponse.arg"

----------------------------------------

-- | Construct a message, a signature of which is attached to every response.
toMessage :: RpcId -> Request -> Response -> BS.ByteString
toMessage rpcId rq rsp = fromRpcId rpcId <> serialise' rq <> serialise' rsp
