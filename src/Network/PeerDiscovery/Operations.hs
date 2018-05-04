module Network.PeerDiscovery.Operations
  ( bootstrap
  , peerLookup
  , handleRequest
  ) where

import Control.Arrow ((&&&))
import Control.Concurrent.Async
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Monad
import Data.Function
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.Map.Strict as M
import qualified Data.Set as S

import Network.PeerDiscovery.Communication
import Network.PeerDiscovery.Routing
import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

-- | Bootstrap the instance with initial peer.
bootstrap
  :: PeerDiscovery cm
  -> Node -- ^ Initial peer
  -> IO Bool
bootstrap pd node = modifyMVar (pdBootstrapped pd) $ \case
  True  -> return (True, True)
  False -> do
    -- Check if the initial peer is alive.
    sendRequestSync pd (Ping Nothing) node (return (False, False)) $ \Pong -> do
      readMVar (pdPublicPort pd) >>= \case
        Nothing   -> return ()
        Just port -> do
          -- Check if we're globally reachable on the specified port.
          reachable <- sendRequestSync pd (Ping $ Just port) node
            (return False)
            (\Pong -> return True)
          -- If we're not, erase the port so we don't pretend in future
          -- communication that we are.
          when (not reachable) $ do
            putStrLn $ "bootstrap: we are not globally reachable on " ++ show port
            modifyMVarP_ (pdPublicPort pd) (const Nothing)
      -- We successfully contacted (and thus authenticated) the initial peer, so
      -- it's safe to insert him into the routing table.
      modifyMVarP_ (pdRoutingTable pd) $ unsafeInsertPeer (pdConfig pd) node
      myId <- withMVarP (pdRoutingTable pd) rtId
      -- Populate our neighbourhood.
      void $ peerLookup pd myId
      fix $ \loop -> do
        targetId <- randomPeerId
        -- Populate part of the routing table holding nodes far from us.
        if testPeerIdBit myId 0 /= testPeerIdBit targetId 0
          then (True, True) <$ peerLookup pd targetId
          else loop

----------------------------------------

-- | Post-processed response of a 'FindNode' request.
data Reply = Success !Node !ReturnNodes
           | Failure !Distance !Node

-- | Perform Kademlia peer lookup operation and return up to k live peers
-- closest to a target id.
peerLookup :: PeerDiscovery cm -> PeerId -> IO [Node]
peerLookup pd@PeerDiscovery{..} targetId = do
  -- We start by taking k peers closest to the target from our routing table.
  closest <- withMVarP pdRoutingTable $ map (distance targetId . nodeId &&& id)
                                      . findClosest (configK pdConfig) targetId
  -- Put ourselves in the initial set of failed peers to avoid contacting
  -- ourselves during lookup as there is no point, we already picked the best
  -- peers we had in the routing table.
  failed <- withMVarP pdRoutingTable (S.singleton . rtId)

  -- We partition k initial peers into (at most) d buckets of similar size to
  -- perform d independent lookups with disjoin routing paths to make it hard
  -- for an adversary to reroute us into the part of network he controls.
  buckets <- randomPartition (configD pdConfig) closest
  let !bucketsLen = length buckets
  -- We share the list of nodes we query to make routing paths disjoint.
  queried <- newMVar M.empty
  -- Perform up to d lookups in parallel.
  results <- forConcurrently buckets $ \bucket -> do
    queue <- newTQueueIO
    outerLoop queue (M.fromList bucket) queried failed

  return . map fst . take (configK pdConfig)
         -- Consider only nodes that were returned by the majority of lookups.
         . filter ((> bucketsLen `quot` 2) . snd)
         -- Count the number of lookups that returned a specific node.
         . M.toList . M.fromListWith (+) . map (, 1::Int)
         $ concat results
  where
    outerLoop
      :: TQueue Reply
      -> M.Map Distance Node
      -> MVar (M.Map Distance Node)
      -> S.Set PeerId
      -> IO [Node]
    outerLoop queue closest queried failed = do
      -- We select alpha peers from the k closest ones we didn't yet query.
      chosen <- peersToQuery queried (configAlpha pdConfig) closest
      if null chosen
        -- If there isn't anyone left to query, the lookup is done.
        then return . M.elems $ M.take (configK pdConfig) closest
        else do
          sendFindNodeRequests queue chosen
          -- Process responses from chosen peers and update the list of closest
          -- and queried peers accordingly.
          (newClosest, newFailed) <-
            processResponses queue queried (length chosen) closest failed

          -- We returned from processResponses which indicates that the closest
          -- peer didn't change (as if it did, we would send more FindNode
          -- requests), so now we send FindNode requests to all of the k closest
          -- peers we didn't yet query.
          rest <- peersToQuery queried (configK pdConfig) newClosest
          sendFindNodeRequests queue rest
          (newerClosest, newerFailed) <-
            processResponses queue queried (length rest) newClosest newFailed

          outerLoop queue newerClosest queried newerFailed

    -- Select a number of chosen peers from the k closest ones we didn't yet
    -- query to send them FindNode requests and mark them as queried so parallel
    -- lookups will not select them as we want routing paths to be disjoint.
    peersToQuery
      :: MVar (M.Map Distance Node)
      -> Int
      -> M.Map Distance Node
      -> IO ([(Distance, Node)])
    peersToQuery mvQueried n closest = modifyMVarP mvQueried $ \queried ->
      let chosen = M.take n $ (M.take (configK pdConfig) closest) M.\\ queried
      in (queried `M.union` chosen, M.toList chosen)

    -- Asynchronously send FindNode requests to multiple peers and put the
    -- responses in a queue so we can synchronously process them as they come.
    sendFindNodeRequests
      :: TQueue Reply
      -> [(Distance, Node)]
      -> IO ()
    sendFindNodeRequests queue peers = do
      publicPort <- readMVar pdPublicPort
      myId <- withMVarP pdRoutingTable rtId
      let findNode = FindNode { fnPeerId = myId
                              , fnPublicPort = publicPort
                              , fnTargetId = targetId
                              }
      forM_ peers $ \(targetDist, peer) -> sendRequest pd findNode peer
        (atomically . writeTQueue queue $ Failure targetDist peer)
        (\response@(ReturnNodes nodes) ->
           -- Do not accept responses with more than k nodes.
           atomically . writeTQueue queue $! if length nodes <= configK pdConfig
                                             then Success peer response
                                             else Failure targetDist peer)

    processResponses
      :: TQueue Reply
      -> MVar (M.Map Distance Node)
      -> Int
      -> M.Map Distance Node
      -> S.Set PeerId
      -> IO (M.Map Distance Node, S.Set PeerId)
    processResponses queue queried = innerLoop
      where
        innerLoop
          :: Int
          -> M.Map Distance Node
          -> S.Set PeerId
          -> IO (M.Map Distance Node, S.Set PeerId)
        innerLoop pending closest failed = case pending of
          -- If there are no more pending replies, we completed the round.
          0 -> return (closest, failed)
          _ -> do
            reply <- atomically (readTQueue queue)
            case reply of
              -- We got the list of peers from the recipient. Put the recipient
              -- into the routing table, update our list of peers closest to the
              -- target and mark the peer as queried.
              Success peer (ReturnNodes peers) -> do
                -- We successfully contacted (and thus authenticated) the peer,
                -- so it's safe to put him into the routing table.
                modifyMVarP_ pdRoutingTable $ unsafeInsertPeer pdConfig peer

                let newClosest = updateClosestWith failed closest peers
                -- If the closest peer changed, send another round of FindNode
                -- requests. Note that it's safe to call findMin here as closest
                -- can't be empty (we wouldn't be here if it was) and we just
                -- received peers, so newClosest also can't be empty.
                newPending <- case M.findMin closest == M.findMin newClosest of
                  True  -> return $ pending - 1
                  False -> do
                    chosen <- peersToQuery queried (configAlpha pdConfig) closest
                    sendFindNodeRequests queue chosen
                    return $ pending + length chosen - 1

                innerLoop newPending newClosest failed

              -- If FindNode request failed, remove the recipient from the list
              -- of closest peers and mark it as failed so that we won't add it
              -- to the list of closest peers again during the rest of the
              -- lookup.
              Failure targetDist peer -> do
                modifyMVarP_ pdRoutingTable $ timeoutPeer peer
                innerLoop (pending - 1) (M.delete targetDist closest)
                          (S.insert (nodeId peer) failed)

        updateClosestWith
          :: S.Set PeerId
          -> M.Map Distance Node
          -> [Node]
          -> M.Map Distance Node
        updateClosestWith failed closest =
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
          M.take ((configAlpha pdConfig + 1) * configK pdConfig) . foldr f closest
          where
            f peer acc =
              -- If a peer failed to return a response during lookup at any
              -- point, we won't consider it a viable candidate for the whole
              -- lookup duration even if other peers keep returning it.
              if nodeId peer `S.member` failed
              then acc
              else M.insert (distance targetId $ nodeId peer) peer acc

----------------------------------------

-- | Handle appropriate 'Request'.
handleRequest :: PeerDiscovery cm -> Peer -> RpcId -> Request -> IO ()
handleRequest pd@PeerDiscovery{..} peer rpcId req = case req of
  FindNodeR FindNode{..} -> do
    peers <- modifyMVar pdRoutingTable $ \oldTable -> do
      let mnode = fnPublicPort <&> \port ->
            Node { nodeId   = fnPeerId
                 , nodePeer = peer { peerPort = port }
                 }
      -- If we got a port number, we assume that peer is globally reachable
      -- under his IP address and received port number, so we insert him into
      -- our routing table. In case he lied it's not a big deal, he either won't
      -- make it or will be evicted soon.
      !table <- readMVar pdBootstrapped >>= \case
        -- Do not modify routing table until bootstrap was completed. This
        -- prevents an attacker from spamming us with requests during bootstrap
        -- phase and possibly gaining large influence in the routing table.
        False -> return oldTable
        True  -> case mnode of
          -- If it comes to nodes who send us requests, we only insert them into
          -- the table if the highest bit of their id is different than
          -- ours. This way a potential adversary:
          --
          -- 1) Can't directly influence our neighbourhood by flooding us with
          -- reqeusts from nodes that are close to us.
          --
          -- 2) Will have a hard time getting a large influence in our routing
          -- table because the branch representing different highest bit
          -- accounts for half of the network, so its buckets will most likely
          -- be full.
          Just node
            | testPeerIdBit fnPeerId 0 /= testPeerIdBit (rtId oldTable) 0 ->
              case insertPeer pdConfig node oldTable of
                Right newTable -> return newTable
                Left oldNode -> do
                  -- Either the node address changed or we're dealing with an
                  -- impersonator, so we only update the address if we don't get
                  -- a response from the old address and we get a response from
                  -- the new one. Note that simply pinging the new address is
                  -- not sufficient, as an impersonator can forward ping request
                  -- to the existing node and then forward his response back to
                  -- us. He won't be able to modify the subsequent traffic
                  -- (because he can't respond to requests on its own as he
                  -- lacks the appropriate private kay), but he can block it.
                  sendRequest pd (Ping Nothing) oldNode
                    (sendRequest pd (Ping Nothing) node
                      (return ())
                      (\Pong ->
                         modifyMVarP_ pdRoutingTable $ unsafeInsertPeer pdConfig node))
                    (\Pong -> return ())
                  return oldTable
            | otherwise ->
              -- If the highest bit is the same, we at most reset timeout count
              -- of the node if it's in our routing table.
              return $ clearTimeoutPeer node oldTable
          _ -> return oldTable
      return (table, findClosest (configK pdConfig) fnTargetId table)
    sendResponse peer $ ReturnNodesR (ReturnNodes peers)
  PingR Ping{..} ->
    -- If port number was specified, respond there.
    let receiver = maybe peer (\port -> peer { peerPort = port }) pingReturnPort
    in sendResponse receiver $ PongR Pong
  where
    sendResponse receiver rsp =
      let signature = C.sign pdSecretKey pdPublicKey (toMessage rpcId req rsp)
      in sendTo pdCommInterface receiver $ Response rpcId pdPublicKey signature rsp
