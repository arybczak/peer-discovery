module Network.PeerDiscovery
  ( withPeerDiscovery
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Exception
import Network.Socket
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Workers

-- | Start peer discovery instance.
withPeerDiscovery
  :: Config            -- ^ Instance configuration parameters.
  -> Bool              -- ^ Specify whether you want to join the network. If you
                       -- are behind NAT, you need to make sure that you are
                       -- reachable on the port specified below.
  -> Maybe C.SecretKey -- ^ Secret key for the instance. If none is given,
                       -- freshly generated key will be used.
  -> Maybe HostName    -- ^ Host name to bind to, if applicable.
  -> PortNumber        -- ^ Port number to bind to.
  -> (PeerDiscovery -> IO r)
  -> IO r
withPeerDiscovery pdConfig joinNetwork mskey mhost port k = do
  signalQueue        <- newTBQueueIO $ configSignalQueueSize pdConfig
  pdSecretKey        <- maybe C.generateSecretKey pure mskey
  let pdPublicKey    = C.toPublic pdSecretKey
      pdPublicPort   = if joinNetwork then Just port else Nothing
  pdRoutingTable     <- newMVar . initRoutingTable $ mkPeerId pdPublicKey
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
