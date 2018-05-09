{-# LANGUAGE RankNTypes #-}
module Network.PeerDiscovery
  ( withPeerDiscovery
  , findPeers
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Network.Socket hiding (recvFrom, sendTo)
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
  pdBootstrapped     <- newMVar False
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

-- | Find peers to connect to. If peer lookup fails a subsequent number of
-- times, we assume that the routing table is corrupted. We then reset its
-- state, return empty list and require that 'bootstrap' is called to repopulate
-- the routing table.
findPeers :: PeerDiscovery cm -> IO [Peer]
findPeers pd@PeerDiscovery{..} = loop (configLookupTries pdConfig)
  where
    loop :: Int -> IO [Peer]
    loop 0 = do
      -- Peer lookup operation failed to return any peers a couple of times. We
      -- assume that the routing table is somehow corrupted, hence we need to
      -- reset its state and bootstrap the instance again.
      modifyMVar_ pdBootstrapped $ \bootstrapped -> do
        when bootstrapped $ modifyMVar_ pdRoutingTable $ \_ ->
          return . initRoutingTable $ mkPeerId pdPublicKey
        return False
      return []
    loop k = do
      peers <- map nodePeer <$> (peerLookup pd =<< randomPeerId)
      if null peers
        then loop (k - 1)
        else return peers
