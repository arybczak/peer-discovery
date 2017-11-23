module Network.PeerDiscovery.Operations
  ( bootstrap
  , requestAddress
  , peerLookup
  ) where

import Control.Arrow ((&&&))
import Control.Concurrent.STM
import Control.Monad
import Data.List
import Data.Ord
import qualified Data.Map.Strict as M
import qualified Data.Set as S

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

-- | Bootstrap the instance with initial list of peers.
bootstrap
  :: Bool          -- ^ Attempt to join the network
  -> PeerDiscovery
  -> [Peer]        -- ^ Initial peers
  -> IO ()
bootstrap joinNetwork pd peers = do
  -- Insert initial peer into the routing table so that we have peers to query.
  modifyMVarP_ (pdRoutingTable pd) $ \table ->
    foldr (insertPeer $ pdConfig pd) table peers
  mMe <- if joinNetwork
    then fmap mkNode <$> requestAddress pd
    else return Nothing
  case mMe of
    Just me -> do
      -- We don't need to rebuild the routing table at this point, there is too
      -- little entries in it for the id to matter.
      modifyMVarP_ (pdRoutingTable pd) $ \table -> table { rtMe = Just me }
      -- Poplate the neighbourhood by requesting peers closest to us.
      void $ peerLookup pd (nodeId me)
    Nothing ->
      -- If we're not joining, issue a lookup for random peer to populate the
      -- routing table.
      void $ peerLookup pd =<< randomPeerId

-- | Request from other peers the address they see us at.
requestAddress :: PeerDiscovery -> IO (Maybe Peer)
requestAddress pd = do
  queue <- newTQueueIO
  peers <- peerLookup pd =<< randomPeerId
  forM_ peers $ \peer -> do
    sendRequest pd (RequestAddress $ peerPort (pdBindAddr pd)) peer
      (atomically $ writeTQueue queue Nothing)
      (\(AddressableAs addr) -> atomically $ writeTQueue queue (Just addr))
  determineAddress queue M.empty (length peers)
  where
    determineAddress
      :: TQueue (Maybe Peer)
      -> M.Map Peer Int
      -> Int
      -> IO (Maybe Peer)
    determineAddress queue addrs = \case
      0 -> case M.toList addrs of
        -- No response got through, we are not reachable.
        []          -> return Nothing
        -- Everyone agreed on the address, just return it.
        [(addr, _)] -> return $ Just addr
        -- There were multiple answers. There are two possibilities, either we
        -- contacted nodes both inside and outside the private network we're in
        -- or someone lied. In such case we pick an address returned by the
        -- majority of peers.
        xs -> let (addr, p1) : (_, p2) : _ = sortBy (comparing $ Down . snd) xs
              in if p1 > p2
                 -- If there is a clear winner, we are done.
                 then return $ Just addr
                 -- If there is a tie, start over with a different set of peers.
                 else requestAddress pd

      k -> atomically (readTQueue queue) >>= \case
        Nothing   -> determineAddress queue addrs (k - 1)
        Just addr -> determineAddress queue (M.insertWith (+) addr 1 addrs) (k - 1)

----------------------------------------

-- | Post-processed response of a 'FindPeer' request.
data Reply = Success !Integer !Peer !ReturnPeers
           | Failure !Integer !Peer

-- | Perform Kademlia peer lookup operation and return up to k live peers
-- closest to a target id.
peerLookup :: PeerDiscovery -> PeerId -> IO [Peer]
peerLookup pd@PeerDiscovery{..} targetId = do
  queue <- newTQueueIO
  -- We start by taking k peers closest to the target from our routing table.
  closest <- withMVarP pdRoutingTable $ M.fromList
                                      . map (distance targetId . mkPeerId &&& id)
                                      . findClosest (configK pdConfig) targetId
  outerLoop queue closest M.empty S.empty
  where
    outerLoop
      :: TQueue Reply
      -> M.Map Integer Peer
      -> M.Map Integer Peer
      -> S.Set Peer
      -> IO [Peer]
    outerLoop queue closest visited failed = do
      -- We select alpha peers from the k closest ones we didn't yet visit.
      let chosen = peersToQuery (configAlpha pdConfig) closest visited
      if null chosen
        -- If there isn't anyone left to query, the lookup is done.
        then return . M.elems $ M.take (configK pdConfig) closest
        else do
          sendFindPeerRequests queue chosen
          -- Process responses from chosen peers and update the list of closest
          -- and visited peers accordingly.
          (newClosest, newVisited, newFailed) <-
            processResponses queue (length chosen) closest visited failed

          -- We returned from processResponses which indicates that the closest
          -- peer didn't change (as if it did, we would send more FindPeer
          -- requests), so now we send FindPeer requests to all of the k closest
          -- peers we didn't yet query.
          let rest = peersToQuery (configK pdConfig) newClosest newVisited
          sendFindPeerRequests queue rest
          (newerClosest, newerVisited, newerFailed) <-
            processResponses queue (length rest) newClosest newVisited newFailed

          outerLoop queue newerClosest newerVisited newerFailed

    -- Get peers to send FindNode to from the k closest peers we didn't yet
    -- query.
    peersToQuery
      :: Int
      -> M.Map Integer Peer
      -> M.Map Integer Peer
      -> [(Integer, Peer)]
    peersToQuery n closest visited =
      M.toList . M.take n $ (M.take (configK pdConfig) closest) M.\\ visited

    -- Asynchronously send FindPeer requests to multiple peers and put the
    -- responses in a queue so we can synchronously process them as they come.
    sendFindPeerRequests
      :: TQueue Reply
      -> [(Integer, Peer)]
      -> IO ()
    sendFindPeerRequests queue peers = do
      -- If we are addressable, include the port in the request so that the
      -- recipient can add us into its routing table.
      mport <- fmap (peerPort . nodePeer) <$> withMVarP pdRoutingTable rtMe
      forM_ peers $ \(targetDist, peer) -> do
        sendRequest pd (FindPeer mport targetId) peer
          (atomically . writeTQueue queue $ Failure targetDist peer)
          (atomically . writeTQueue queue . Success targetDist peer)

    processResponses
      :: TQueue Reply
      -> Int
      -> M.Map Integer Peer
      -> M.Map Integer Peer
      -> S.Set Peer
      -> IO (M.Map Integer Peer, M.Map Integer Peer, S.Set Peer)
    processResponses queue = innerLoop
      where
        innerLoop
          :: Int
          -> M.Map Integer Peer
          -> M.Map Integer Peer
          -> S.Set Peer
          -> IO (M.Map Integer Peer, M.Map Integer Peer, S.Set Peer)
        innerLoop pending closest visited failed = case pending of
          -- If there are no more pending replies, we completed the round.
          0 -> return (closest, visited, failed)
          _ -> do
            reply <- atomically (readTQueue queue)
            case reply of
              -- We got the list of peers from the recipient. Put the recipient
              -- into the routing table, update our list of peers closest to the
              -- target and mark the peer as visited.
              Success targetDist peer (ReturnPeers peers) -> do
                modifyMVarP_ pdRoutingTable $ insertPeer pdConfig peer
                let newClosest = updateClosestWith failed closest peers

                -- If the closest peer changed, send another round of FindNode
                -- requests. Note that it's safe to call findMin here as closest
                -- can't be empty (we wouldn't be here if it was) and we just
                -- received peers, so newClosest also can't be empty.
                newPending <- case M.findMin closest == M.findMin newClosest of
                  True  -> return $ pending - 1
                  False -> do
                    let chosen = peersToQuery (configAlpha pdConfig) closest visited
                    sendFindPeerRequests queue chosen
                    return $ pending + length chosen - 1

                innerLoop newPending newClosest (M.insert targetDist peer visited)
                                                failed

              -- If FindPeer request failed, remove the recipient from the list
              -- of closest peers and mark it as failed so that we won't add it
              -- to the list of closest peers again during the rest of the
              -- lookup.
              Failure targetDist peer -> do
                modifyMVarP_ pdRoutingTable $ timeoutPeer peer
                innerLoop (pending - 1) (M.delete targetDist closest)
                          visited (S.insert peer failed)

        updateClosestWith
          :: S.Set Peer
          -> M.Map Integer Peer
          -> [Peer]
          -> M.Map Integer Peer
        updateClosestWith failed peers =
          -- We need to keep more than k peers on the list. If we keep k, then
          -- the following might happen: we're in the middle of the lookup, we
          -- send queries to alpha closest peers. We get the responses, closest
          -- peer stays the same. We then send queries to all of the remaining k
          -- peers we didn't yet query. One or more of them fails (and we'll
          -- usually handle failure (timeout) as the last event, so the list of
          -- closest peers will not be updated anymore during this round). We
          -- remove it from the list of closest peers and we're ready for the
          -- next round to fill the gap, but now we don't have anyone left to
          -- query (because we just did) and we also have less than k closest
          -- peers.
          M.take ((configAlpha pdConfig + 1) * configK pdConfig) . foldr f peers
          where
            f peer acc =
              -- If a peer failed to return a response during lookup at any
              -- point, we won't consider it a viable candidate for the whole
              -- lookup duration even if other peers keep returning it.
              if peer `S.member` failed
              then acc
              else M.insert (distance targetId $ mkPeerId peer) peer acc
