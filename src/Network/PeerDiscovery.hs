{-# LANGUAGE RankNTypes #-}
module Network.PeerDiscovery
  ( withPeerDiscovery
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Network.Socket hiding (recvFrom, sendTo)
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M

import Network.PeerDiscovery.Communication.Method
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
  pdPublicPort       <- newMVar $ if joinNetwork then Just port else Nothing
  pdSecretKey        <- maybe C.generateSecretKey pure mskey
  let pdPublicKey    = C.toPublic pdSecretKey
  pdRoutingTable     <- newMVar . initRoutingTable $ mkPeerId pdPublicKey
  pdResponseHandlers <- newMVar M.empty
  commMethod port $ \pdBindAddr pdCommInterface -> do
    let pd = PeerDiscovery{..}
    withAsync (dispatcher pd) $ \_ -> k pd
