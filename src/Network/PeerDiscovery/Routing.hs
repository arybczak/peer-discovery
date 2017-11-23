module Network.PeerDiscovery.Routing
  ( initRoutingTable
  , insertPeer
  , timeoutPeer
  , findClosest
  ) where

import Data.Maybe
import qualified Data.Foldable as F
import qualified Data.Sequence as S

import Network.PeerDiscovery.Types

initRoutingTable :: Maybe Peer -> RoutingTable
initRoutingTable mpeer =
  RoutingTable { rtMe = mkNode <$> mpeer
               , rtTree = Bucket S.empty
               }

insertPeer :: Config -> Peer -> RoutingTable -> RoutingTable
insertPeer conf peer rt = rt { rtTree = go (isJust myId) 0 (rtTree rt) }
  where
    myId = nodeId <$> rtMe rt

    node = NodeInfo { niNode         = mkNode peer
                    , niTimeoutCount = 0
                    }

    go :: Bool -> Int -> RoutingTree -> RoutingTree
    go !myBranch !depth = \case
      tree@(Bucket nodes) -> if
        | S.length nodes < configK conf ->
          -- Check if a node is already there and if so, update its last seen
          -- field, reset its timeout count and put it at the head of the
          -- list. If it's not, simply insert it at the head.
          case S.findIndexL ((== peer) . nodePeer . niNode) nodes of
            Just nodeIdx -> Bucket $ node S.<| S.deleteAt nodeIdx nodes
            Nothing      -> Bucket $ node S.<|                    nodes
        | myBranch || depth < configB conf ->
            -- If we are in a branch that represents prefix of our id or we are
            -- above max depth, split existing bucket into two and recursively
            -- select the appropriate one.
            --
            -- Note that if we don't have an id (meaning that we didn't join the
            -- network) we treat all branches equally, i.e. we split them only
            -- until a certain depth is reached.
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
        let peerBit      = testPeerIdBit (nodeId $ niNode node) depth
            -- If there is no id, use error as && will not reach it.
            myBit        = maybe (error "insertPeer") (`testPeerIdBit` depth) myId
            -- Check whether the branch we're going to extends our id prefix.
            nextMyBranch = myBranch && myBit == peerBit
        in if peerBit
        then Split (go nextMyBranch (depth + 1) left) right
        else Split left (go nextMyBranch (depth + 1) right)

-- | Increase the count of timeouts of a given peer by 1.
timeoutPeer :: Peer -> RoutingTable -> RoutingTable
timeoutPeer peer rt = rt { rtTree = go 0 (rtTree rt) }
  where
    nid = mkPeerId peer

    go !depth = \case
      tree@(Bucket nodes) ->
        case S.findIndexR ((== peer) . nodePeer . niNode) nodes of
          Just nodeIdx ->
            let f node = node { niTimeoutCount = niTimeoutCount node + 1 }
            in Bucket $ S.adjust' f nodeIdx nodes
          Nothing -> tree
      Split left right ->
        if testPeerIdBit nid depth
        then Split (go (depth + 1) left) right
        else Split left (go (depth + 1) right)

-- | Return up to k peers closest to the target id.
findClosest :: Int -> PeerId -> RoutingTable -> [Peer]
findClosest n nid = F.foldr (\node acc -> nodePeer (niNode node) : acc) []
                  . go n 0 . rtTree
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
