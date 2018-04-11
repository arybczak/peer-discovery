module Network.PeerDiscovery.Workers
  ( dispatcher
  ) where

import Control.Concurrent
import Control.Monad

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Types

-- | Handle all incoming signals, both requests and responses.
dispatcher :: PeerDiscovery cm -> IO r
dispatcher pd = forever $ do
  signal <- recvFrom (pdCommInterface pd)
  forkIO $ case signal of
    (peer, Request rpcId rq) -> handleRequest pd peer rpcId rq
    (peer, Response rpcId pkey signature rsp) ->
      handleResponse (pdResponseHandlers pd) peer rpcId pkey signature rsp
