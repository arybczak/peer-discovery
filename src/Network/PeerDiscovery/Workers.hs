module Network.PeerDiscovery.Workers
  ( receiver
  , dispatcher
  ) where

import Control.Concurrent.STM
import Control.Monad
import Network.Socket hiding (recvFrom, sendTo)
import Network.Socket.ByteString

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

-- | Continously retrieve data from the socket, parse it as Signal and put into
-- queue for further processing by 'dispatcher'.
receiver :: Socket -> TBQueue (Peer, Signal) -> IO r
receiver sock queue = forever $ do
  (bytes, source) <- recvFrom sock 512
  case mkPeer source of
    Nothing -> putStrLn $ "receiver: couldn't construct Peer from " ++ show source
    Just peer -> case deserialiseOrFail' bytes of
      Right signal -> atomically $ writeTBQueue queue (peer, signal)
      Left err -> putStrLn $ "receiver: error while parsing signal: " ++ show err

-- | Handle all incoming signals, both requests and responses.
dispatcher :: PeerDiscovery -> TBQueue (Peer, Signal) -> IO r
dispatcher pd queue = do
  forever $ atomically (readTBQueue queue) >>= \case
    (peer, Request rpcId rq)   -> handleRequest pd peer rpcId rq
    (peer, Response rpcId rsp) -> handleResponse (pdResponseHandlers pd) peer rpcId rsp
