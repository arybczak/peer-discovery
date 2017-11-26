module Network.PeerDiscovery.Operations
  ( bootstrap
  , peerLookup
  ) where

import Control.Arrow ((&&&))
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Monad
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M
import qualified Data.Set as S

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

-- | Bootstrap the instance with initial peer.
bootstrap
  :: PeerDiscovery
  -> Node -- ^ Initial peer
  -> IO ()
bootstrap pd node = do
  nonce  <- randomNonce
  result <- newEmptyMVar
  -- Check authenticity of initial peer.
  sendRequest pd (RequestAuth nonce) (nodePeer node)
    (putMVar result Nothing)
    (\(AuthProof pkey signature) ->
       if nodeId node == mkPeerId pkey && C.verify pkey nonce signature
       then do
         modifyMVarP_ (pdRoutingTable pd) $ insertPeer (pdConfig pd) node
         putMVar result (Just True)
       else putMVar result (Just False))

  readMVar result >>= \case
    Nothing    -> error "bootstrap: couldn't connect to peer"
    Just False -> error "bootstrap: peer authorization failed"
    Just True  -> do
      -- If verification went fine, populate the neighbourhood.
      void $ peerLookup pd =<< withMVarP (pdRoutingTable pd) rtId

----------------------------------------

-- | Post-processed response of a 'FindNode' request.
data Reply = Success !Integer !Node !ReturnNodes
           | Failure !Integer !Node

-- | Perform Kademlia peer lookup operation and return up to k live peers
-- closest to a target id.
peerLookup :: PeerDiscovery -> PeerId -> IO [Node]
peerLookup pd@PeerDiscovery{..} targetId = do
  queue <- newTQueueIO
  -- We start by taking k peers closest to the target from our routing table.
  closest <- withMVarP pdRoutingTable $ M.fromList
                                      . map (distance targetId . nodeId &&& id)
                                      . findClosest (configK pdConfig) targetId
  outerLoop queue closest M.empty S.empty
  where
    outerLoop
      :: TQueue Reply
      -> M.Map Integer Node
      -> M.Map Integer Node
      -> S.Set PeerId
      -> IO [Node]
    outerLoop queue closest visited failed = do
      -- We select alpha peers from the k closest ones we didn't yet visit.
      let chosen = peersToQuery (configAlpha pdConfig) closest visited
      if null chosen
        -- If there isn't anyone left to query, the lookup is done.
        then return . M.elems $ M.take (configK pdConfig) closest
        else do
          sendFindNodeRequests queue chosen
          -- Process responses from chosen peers and update the list of closest
          -- and visited peers accordingly.
          (newClosest, newVisited, newFailed) <-
            processResponses queue (length chosen) closest visited failed

          -- We returned from processResponses which indicates that the closest
          -- peer didn't change (as if it did, we would send more FindNode
          -- requests), so now we send FindNode requests to all of the k closest
          -- peers we didn't yet query.
          let rest = peersToQuery (configK pdConfig) newClosest newVisited
          sendFindNodeRequests queue rest
          (newerClosest, newerVisited, newerFailed) <-
            processResponses queue (length rest) newClosest newVisited newFailed

          outerLoop queue newerClosest newerVisited newerFailed

    -- Select a number of chosen peers from the k closest ones we didn't yet
    -- query to send them FindNode requests.
    peersToQuery
      :: Int
      -> M.Map Integer Node
      -> M.Map Integer Node
      -> [(Integer, Node)]
    peersToQuery n closest visited =
      M.toList . M.take n $ (M.take (configK pdConfig) closest) M.\\ visited

    -- Asynchronously send FindNode requests to multiple peers and put the
    -- responses in a queue so we can synchronously process them as they come.
    sendFindNodeRequests
      :: TQueue Reply
      -> [(Integer, Node)]
      -> IO ()
    sendFindNodeRequests queue peers = do
      myId <- withMVarP pdRoutingTable rtId
      forM_ peers $ \(targetDist, peer) -> do
        sendRequest pd (FindNode myId pdPublicPort targetId) (nodePeer peer)
          (atomically . writeTQueue queue $ Failure targetDist peer)
          (atomically . writeTQueue queue . Success targetDist peer)

    processResponses
      :: TQueue Reply
      -> Int
      -> M.Map Integer Node
      -> M.Map Integer Node
      -> S.Set PeerId
      -> IO (M.Map Integer Node, M.Map Integer Node, S.Set PeerId)
    processResponses queue = innerLoop
      where
        innerLoop
          :: Int
          -> M.Map Integer Node
          -> M.Map Integer Node
          -> S.Set PeerId
          -> IO (M.Map Integer Node, M.Map Integer Node, S.Set PeerId)
        innerLoop pending closest visited failed = case pending of
          -- If there are no more pending replies, we completed the round.
          0 -> return (closest, visited, failed)
          _ -> do
            reply <- atomically (readTQueue queue)
            case reply of
              -- We got the list of peers from the recipient. Put the recipient
              -- into the routing table, update our list of peers closest to the
              -- target and mark the peer as visited.
              Success targetDist peer (ReturnNodes peers) -> do
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
                    sendFindNodeRequests queue chosen
                    return $ pending + length chosen - 1

                innerLoop newPending newClosest (M.insert targetDist peer visited)
                                                failed

              -- If FindNode request failed, remove the recipient from the list
              -- of closest peers and mark it as failed so that we won't add it
              -- to the list of closest peers again during the rest of the
              -- lookup.
              Failure targetDist peer -> do
                modifyMVarP_ pdRoutingTable $ timeoutPeer peer
                innerLoop (pending - 1) (M.delete targetDist closest)
                          visited (S.insert (nodeId peer) failed)

        updateClosestWith
          :: S.Set PeerId
          -> M.Map Integer Node
          -> [Node]
          -> M.Map Integer Node
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
              if nodeId peer `S.member` failed
              then acc
              else M.insert (distance targetId $ nodeId peer) peer acc
