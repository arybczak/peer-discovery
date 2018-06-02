module Network.PeerDiscovery.Workers
  ( refresher
  , dispatcher
  ) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Monad
import Data.Maybe
import Prelude
import qualified Data.Sequence as S
import qualified Data.Foldable as F
import qualified Data.Traversable as F

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

refresher :: PeerDiscovery cm -> IO r
refresher pd@PeerDiscovery{..} = forever $ do
  threadDelay $ (5 * minute) `quot` configSpeedupFactor pdConfig
  -- Perform random peer lookup each 5 minutes in order to keep the routing
  -- table fresh.
  void $ peerLookup pd =<< randomPeerId
  -- Test connectivity of nodes in the routing table that failed to return the
  -- response to FindNode request by periodically sending them random FindNode
  -- requests (note that we can't use Ping requests for that as in principle a
  -- node might ignore all FindNode requests, but respond to Ping request and
  -- occupy a space in our routing table while being useless).
  --
  -- If any of them consecutively fails to respond a specific number of times,
  -- we then check whether the replacement cache of the corresponding bucket is
  -- not empty and replace it with the first node from the cache that responds
  -- (if replacement cache is empty, we leave it be).
  --
  -- Note that the whole policy is strategically constructed so that in case of
  -- network failure (i.e. all nodes stop responding) we don't modify the
  -- structure of the routing table (except of increasing timeout counts).
  findNode <- do
    publicPort <- readMVar pdPublicPort
    myId <- withMVarP pdRoutingTable rtId
    return $ \nid -> FindNode { fnPeerId     = myId
                              , fnPublicPort = publicPort
                              , fnTargetId   = nid
                              }
  modifyMVar_ pdRoutingTable $ \table -> do
    -- TODO: might use forConcurrently here to speed things up.
    tree <- F.forM (rtTree table) $ \bucket -> do
      queue <- newTQueueIO
      let timedout = catMaybes . F.toList $ S.mapWithIndex
            (\i ni -> if niTimeoutCount ni > 0 then Just (i, ni) else Nothing)
            (bucketNodes bucket)
      F.forM_ timedout $ \(i, ni@NodeInfo{..}) -> do
        targetId <- randomPeerId
        sendRequest pd (findNode targetId) niNode
          (      atomically $ writeTQueue queue (i, ni, False))
          (\_ -> atomically $ writeTQueue queue (i, ni, True))
      updateBucket findNode queue (length timedout) bucket Nothing
    return table { rtTree = tree }
  where
    minute = 60 * 1000000

    updateBucket
      :: (PeerId -> FindNode)
      -> TQueue (Int, NodeInfo, Bool)
      -> Int
      -> Bucket
      -> Maybe [(Node, Bool)]
      -> IO Bucket
    updateBucket _ _ 0 bucket mcache = case mcache of
      -- If there were no attempts to ping the cache, no node timed out enough
      -- times to be considered for eviction, so just return the updated bucket.
      Nothing -> return bucket
      -- If some nodes timed out enough times to be considered for eviction,
      -- replace the old cache. We ignore whether nodes in cache were alive or
      -- not as it doesn't matter; they will either be ignored during the next
      -- iteration or replaced by new incoming nodes.
      Just cache -> return bucket { bucketCache = map fst cache }
    updateBucket findNode queue k bucket mcache = do
      (i, NodeInfo{..}, respondedCorrectly) <- atomically $ readTQueue queue
      if | respondedCorrectly -> updateBucket findNode queue (k - 1)
                                              (clearTimeoutPeerBucket niNode bucket)
                                              mcache
         | niTimeoutCount >= configMaxTimeouts pdConfig -> do
             cache <- case mcache of
               Just cache -> return cache
               Nothing    -> forConcurrently (bucketCache bucket) $ \node -> do
                 targetId <- randomPeerId
                 (node, ) <$> sendRequestSync pd (findNode targetId) node
                   (      return False)
                   (\_ -> return True)
             case break snd cache of
               (dead, (alive, _) : rest) ->
                 -- Pick the first alive node in the cache and replace the dead
                 -- one in the bucket with it.
                 let newNodeInfo = NodeInfo
                       { niNode         = alive
                       , niTimeoutCount = 0
                       }
                     newBucket = bucket
                       { bucketNodes = S.update i newNodeInfo (bucketNodes bucket)
                       }
                 in updateBucket findNode queue (k - 1) newBucket $ Just (dead ++ rest)
               (_dead, []) ->
                 -- All nodes in the replacement cache are dead - most likely
                 -- explanation is network failure, so we don't do anything in
                 -- this case.
                 updateBucket findNode queue (k - 1) bucket (Just cache)
         | otherwise -> updateBucket findNode queue (k - 1)
                                     (timeoutPeerBucket niNode bucket)
                                     mcache

-- | Handle all incoming signals, both requests and responses.
dispatcher :: PeerDiscovery cm -> IO r
dispatcher pd = forever $ do
  signal <- recvFrom (pdCommInterface pd)
  forkIO $ case signal of
    (peer, Request rpcId rq) -> handleRequest pd peer rpcId rq
    (peer, Response rpcId pkey signature rsp) ->
      handleResponse pd peer rpcId pkey signature rsp
