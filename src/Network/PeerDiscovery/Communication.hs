module Network.PeerDiscovery.Communication
  ( sendRequest
  , sendRequestSync
  , handleResponse
  , toMessage
  ) where

import Control.Concurrent
import Control.Monad
import Data.Monoid
import Data.Typeable
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

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
  => PeerDiscovery cm
  -> req                         -- ^ Request to be sent
  -> Node                        -- ^ Recipient
  -> IO ()                       -- ^ Action to perform on failure
  -> (ResponseType req -> IO ()) -- ^ Action to perform on success
  -> IO ()
sendRequest pd reqType peer onFailure onSuccess = do
  rpcId <- randomRpcId
  let request = toRequest reqType
  modifyMVar_ (pdResponseHandlers pd) $ \handlers -> do
    tid <- forkIO (timeoutHandler rpcId)
    let handler = ResponseHandler { rhRequest          = request
                                  , rhRecipient        = peer
                                  , rhTimeoutHandlerId = tid
                                  , rhOnFailure        = onFailure
                                  , rhHandler          = onSuccess
                                  }
    return $! M.insert rpcId handler handlers
  -- Send the request after the response handler was put in place to
  -- make sure that the response is not received before.
  sendTo (pdCommInterface pd) (nodePeer peer) (Request rpcId request)
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
        putStrLn $ "Request " ++ show reqType ++ " sent to "
                ++ show (nodePeer peer) ++ " with " ++ show rpcId ++ " timed out"
        onFailure

-- | Synchronous variant of 'sendRequest'.
sendRequestSync
  :: (IsRequest req, Show req)
  => PeerDiscovery cm
  -> req                        -- ^ Request to be sent
  -> Node                       -- ^ Recipient
  -> IO r                       -- ^ Action to perform on failure
  -> (ResponseType req -> IO r) -- ^ Action to perform on success
  -> IO r
sendRequestSync pd reqType peer onFailure onSuccess = do
  result <- newEmptyMVar
  sendRequest pd reqType peer
    (putMVar result =<< onFailure)
    ((putMVar result =<<) . onSuccess)
  readMVar result

----------------------------------------

-- | Handle 'Response' signals by looking up and running appropriate handler
-- that was registered when a 'Request' was sent.
handleResponse
  :: PeerDiscovery cm
  -> Peer        -- ^ Address of the responder
  -> RpcId       -- ^ Id of the request/response
  -> C.PublicKey -- ^ Public key of the responder
  -> C.Signature -- ^ Signature of the id, request and response
  -> Response
  -> IO ()
handleResponse PeerDiscovery{..} peer rpcId pkey signature rsp = do
  retrieveHandler >>= \case
    Nothing      -> putStrLn $ "handleResponse: no handler for " ++ show rpcId
    Just handler -> case rsp of
      ReturnNodesR returnPeers@(ReturnNodes nodes) ->
        -- We require that length of the list is not longer than configK.
        runHandler handler returnPeers (length nodes <= configK pdConfig)
      PongR pong ->
        runHandler handler pong True
  where
    retrieveHandler = modifyMVarP pdResponseHandlers $ \handlers ->
      case M.lookup rpcId handlers of
        Just handler -> (M.delete rpcId handlers, Just handler)
        Nothing      -> (handlers, Nothing)

    runHandler
      :: forall response. Typeable response
      => ResponseHandler
      -> response
      -> Bool
      -> IO ()
    runHandler ResponseHandler{..} response responseValid = do
      killThread rhTimeoutHandlerId
      if | node /= rhRecipient -> do
             putStrLn $ "handleResponse: response recipient " ++ show rhRecipient
                     ++ " doesn't match the responder: " ++ show node
             rhOnFailure
         | not $ C.verify pkey (toMessage rpcId rhRequest rsp) signature -> do
             putStrLn $ "handleResponse: signature verification failed"
             rhOnFailure
         | responseValid -> case rhHandler <$> cast response of
             Just run -> run
             Nothing  -> do
               putStrLn $ "handleResponse: expected response of type "
                        ++ show (typeOf (argOf rhHandler)) ++ ", but got "
                        ++ show (typeOf response) ++ " for " ++ show rpcId
               rhOnFailure
         | otherwise -> do
             putStrLn $ "handleResponse: validation of response failed"
             rhOnFailure
      where
        node = Node { nodeId   = mkPeerId pkey
                    , nodePeer = peer
                    }

        argOf :: (r -> IO ()) -> r
        argOf _ = error "handleResponse.argOf"

----------------------------------------

-- | Construct a message, a signature of which is attached to every response.
toMessage :: RpcId -> Request -> Response -> BS.ByteString
toMessage rpcId rq rsp = fromRpcId rpcId <> serialise' rq <> serialise' rsp
