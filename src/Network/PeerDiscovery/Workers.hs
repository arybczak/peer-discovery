module Network.PeerDiscovery.Workers
  ( refresher
  , dispatcher
  ) where

import Control.Concurrent
import Control.Monad

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Types

refresher :: PeerDiscovery cm -> IO r
refresher pd = forever $ do
  threadDelay $ (5 * minute) `quot` configSpeedupFactor (pdConfig pd)
  -- Perform random peer lookup each 5 minutes in order to keep the routing
  -- table fresh.
  void $ peerLookup pd =<< randomPeerId
  where
    minute = 60 * 1000000

-- | Handle all incoming signals, both requests and responses.
dispatcher :: PeerDiscovery cm -> IO r
dispatcher pd = forever $ do
  signal <- recvFrom (pdCommInterface pd)
  forkIO $ case signal of
    (peer, Request rpcId rq) -> handleRequest pd peer rpcId rq
    (peer, Response rpcId pkey signature rsp) ->
      handleResponse (pdResponseHandlers pd) peer rpcId pkey signature rsp
