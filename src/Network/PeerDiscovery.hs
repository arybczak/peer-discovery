module Network.PeerDiscovery
  ( withPeerDiscovery
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Exception
import Network.Socket
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Workers

-- | Start peer discovery instance.
withPeerDiscovery
  :: Config
  -> Maybe HostName
  -> PortNumber
  -> (PeerDiscovery -> IO r)
  -> IO r
withPeerDiscovery pdConfig mhost port k = do
  signalQueue        <- newTBQueueIO $ configSignalQueueSize pdConfig
  pdRoutingTable     <- newMVar (initRoutingTable Nothing)
  pdResponseHandlers <- newMVar M.empty
  withUdpSocket $ \pdBindAddr pdSocket -> let pd = PeerDiscovery{..} in do
    withAsync (receiver pdSocket signalQueue) $ \_ -> do
      withAsync (dispatcher pd signalQueue) $ \_ -> do
        k pd
  where
    withUdpSocket action = do
      getAddrInfo (Just hints) mhost (Just $ show port) >>= \case
        []   -> error $ "withUdpSocket: couldn't create IPv4 UDP socket on port "
                     ++ show port
        (ai:_) -> case mkPeer (addrAddress ai) of
          Nothing -> error $ "withUdpSocket: couldn't create Peer from "
                          ++ show (addrAddress ai)
          Just peer -> do
            sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
            bracket_ (bind sock (addrAddress ai)) (close sock) (action peer sock)
      where
        hints = defaultHints { addrFamily = AF_INET
                             , addrFlags = [AI_PASSIVE]
                             , addrSocketType = Datagram
                             }
