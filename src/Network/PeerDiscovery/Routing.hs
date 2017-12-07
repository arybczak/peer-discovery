module Network.PeerDiscovery.Routing
  ( initRoutingTable
  , insertPeer
  , timeoutPeer
  , clearTimeoutPeer
  , findClosest
  ) where

import qualified Data.Foldable as F
import qualified Data.Sequence as S

import Network.PeerDiscovery.Types

initRoutingTable :: PeerId -> RoutingTable
initRoutingTable peerId =
  RoutingTable { rtId   = peerId
               , rtTree = Bucket S.empty
               }

insertPeer :: Config -> Node -> RoutingTable -> RoutingTable
insertPeer conf peer rt =
  -- We don't want ourselves in the routing table, because we are not interested in "discovering" and talking to ourselves.
  if nodeId peer /= rtId rt
  then rt { rtTree = go True 0 (rtTree rt) }
  else rt
  where
    node = NodeInfo { niNode         = peer
                    , niTimeoutCount = 0
                    }

    go :: Bool -> Int -> RoutingTree -> RoutingTree
    go !myBranch !depth = \case
      tree@(Bucket nodes) -> if
        | S.length nodes < configK conf ->
          -- Check if a node is already there and if so, update its last seen
          -- field, reset its timeout count and put it at the head of the
          -- list. If it's not, simply insert it at the head. TODO: Request
          -- authentication if a node with the same identifier, but different
          -- Peer exists.
          case S.findIndexL ((== nodeId peer) . nodeId . niNode) nodes of
            Just nodeIdx -> Bucket $ node S.<| S.deleteAt nodeIdx nodes
            Nothing      -> Bucket $ node S.<|                    nodes
        | myBranch || depth `rem` configB conf /= 0 ->
            -- If we are in a branch that represents prefix of our id or the
            -- condition taken from the original Kademlia paper (section 4.2) is
            -- met, split existing bucket into two and recursively select the
            -- appropriate one.
            let (left, right) = S.partition ((`testPeerIdBit` depth) . nodeId . niNode)
                                            nodes
            in go myBranch depth $ Split (Bucket left) (Bucket right)
        | otherwise ->
          -- If the bucket is full and we're at max depth, check if there are
          -- nodes that didn't respond a couple of times and if so, replace one
          -- of them.
          case S.findIndexR ((> configMaxTimeouts conf) . niTimeoutCount) nodes of
            Just nodeIdx -> Bucket $ node S.<| S.deleteAt nodeIdx nodes
            Nothing      -> tree
      Split left right ->
        let peerBit = testPeerIdBit (nodeId $ niNode node) depth
            myBit   = testPeerIdBit (rtId rt) depth
            -- Check whether the branch we're going to extends our id prefix.
            nextMyBranch = myBranch && myBit == peerBit
        in if peerBit
        then Split (go nextMyBranch (depth + 1) left) right
        else Split left (go nextMyBranch (depth + 1) right)

-- | Increase the timeout count of a given peer by 1.
timeoutPeer :: Node -> RoutingTable -> RoutingTable
timeoutPeer = modifyTimeoutCount (+1)

-- | Reset the timeout count of a given peer.
clearTimeoutPeer :: Node -> RoutingTable -> RoutingTable
clearTimeoutPeer = modifyTimeoutCount (const 0)

-- | Return up to k peers closest to the target id.
findClosest :: Int -> PeerId -> RoutingTable -> [Node]
findClosest n nid = F.foldr (\node acc -> niNode node : acc) [] . go n 0 . rtTree
  where
    go k !depth = \case
      Bucket nodes     -> S.take k nodes
      Split left right ->
        let bitSet  = testPeerIdBit nid depth
            nodes   = if bitSet
                      then go k (depth + 1) left
                      else go k (depth + 1) right
        in case k - S.length nodes of
          -- If we're missing nodes after picking them from the appropriate
          -- branch, get the rest from the adjacent one.
          missing | missing == 0 -> nodes
                  | otherwise    ->
                    if bitSet
                    then nodes S.>< go missing (depth + 1) right
                    else nodes S.>< go missing (depth + 1) left

----------------------------------------

modifyTimeoutCount :: (Int -> Int) -> Node -> RoutingTable -> RoutingTable
modifyTimeoutCount modify peer rt = rt { rtTree = go 0 (rtTree rt) }
  where
    go !depth = \case
      tree@(Bucket nodes) ->
        case S.findIndexR ((== peer) . niNode) nodes of
          Just nodeIdx ->
            let f node = node { niTimeoutCount = modify (niTimeoutCount node) }
            in Bucket $ S.adjust' f nodeIdx nodes
          Nothing -> tree
      Split left right ->
        if testPeerIdBit (nodeId peer) depth
        then Split (go (depth + 1) left) right
        else Split left (go (depth + 1) right)
