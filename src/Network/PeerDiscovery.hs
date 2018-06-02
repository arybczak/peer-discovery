{-# LANGUAGE RankNTypes #-}
module Network.PeerDiscovery
  ( withPeerDiscovery
  , findPeers
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Monad
import Network.Socket hiding (recvFrom, sendTo)
import Prelude
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Communication.Method
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Workers

-- | Start peer discovery instance.
withPeerDiscovery
  :: Config                     -- ^ Instance configuration parameters.
  -> Bool                       -- ^ Specify whether you want to join the
                                -- network. If you are behind NAT, you need to
                                -- make sure that you are reachable on the port
                                -- specified below.
  -> Maybe C.SecretKey          -- ^ Secret key for the instance. If none is
                                -- given, freshly generated key will be used.
  -> CommunicationMethod cm     -- ^ Communication method
  -> PortNumber                 -- ^ Port number to bind to.
  -> (PeerDiscovery cm -> IO r)
  -> IO r
withPeerDiscovery pdConfig joinNetwork mskey commMethod port k = do
  pdBootstrapState   <- newTVarIO BootstrapNeeded
  pdPublicPort       <- newMVar $ if joinNetwork then Just port else Nothing
  pdSecretKey        <- maybe C.generateSecretKey pure mskey
  let pdPublicKey    = C.toPublic pdSecretKey
  pdRoutingTable     <- newMVar . initRoutingTable $ mkPeerId pdPublicKey
  pdResponseHandlers <- newMVar M.empty
  commMethod port $ \pdBindAddr pdCommInterface ->
    let pd = PeerDiscovery{..}
    in       withAsync (refresher pd)
     $ \_ -> withAsync (dispatcher pd)
     $ \_ -> k pd

-- | Find peers to connect to. If peer lookup fails a subsequent
-- number of times, an empty list is returned. This indicates a
-- network failure or that the routing table is somehow corrupted.
findPeers :: PeerDiscovery cm -> IO [Peer]
findPeers pd@PeerDiscovery{..} = loop (configLookupTries pdConfig)
  where
    loop :: Int -> IO [Peer]
    loop 0 = return []
    loop k = do
      peers <- map nodePeer <$> (peerLookup pd =<< randomPeerId)
      if null peers
        then loop (k - 1)
        else return peers
