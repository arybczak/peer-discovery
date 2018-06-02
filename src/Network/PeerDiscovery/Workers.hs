module Network.PeerDiscovery.Workers
  ( refresher
  , dispatcher
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Prelude

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Types

refresher :: PeerDiscovery cm -> IO r
refresher pd@PeerDiscovery{..} = forever $ do
  threadDelay $ (5 * minute) `quot` configSpeedupFactor pdConfig
  join . atomically $ readTVar pdBootstrapState >>= \case
    BootstrapNeeded     -> retry
    BootstrapInProgress -> retry
    BootstrapDone       -> return $ do
      -- Before we do routing table maintenance, perform random peer lookup in
      -- order to refresh the routing table a bit.
      void $ peerLookup pd =<< randomPeerId
      performRoutingTableMaintenance pd
  where
    minute = 60 * 1000000

-- | Handle all incoming signals, both requests and responses.
dispatcher :: PeerDiscovery cm -> IO r
dispatcher pd = forever $ do
  signal <- recvFrom (pdCommInterface pd)
  forkIO $ case signal of
    (peer, Request rpcId rq) -> handleRequest pd peer rpcId rq
    (peer, Response rpcId pkey signature rsp) ->
      handleResponse pd peer rpcId pkey signature rsp
