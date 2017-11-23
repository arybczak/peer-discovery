module Main where

import Control.Concurrent
import Control.Monad
import Network.Socket
import Text.Pretty.Simple

import Network.PeerDiscovery
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Types

-- | Notes
--
-- TODO:
--
-- - Thread for periodically refreshing routing table (calling peer lookup) and
--   requesting address every N lookups to check whether routing table needs to
--   be rebuilt in case our address changed.
--
-- - Replacement cache in the routing table.
--
-- - Abstract the network layer away to be able to use mockup routing for
--   large-scale testing.
--
-- - Prevent ourselves from entering the routing table and being part of the
--   result of peer lookup - we don't want to talk to ourselves.
--
-- NOT CLEAR:
--
-- - Exclude peers with non-zero amount of timeouts from being returned by
--   findClosest (most likely makes sense).
--
-- - Additional thread for periodically pinging peers with non-zero amount of
--   timeouts to speed up their eviction (possibly necessary if we do the
--   above).
--
-- ----------------------------------------
--
-- 1. IPv6 support - requires two instances, one for IPv4 and one for IPv6 - we
-- can't mix these two. Relatively easy to add. Alternative below.
--
-- IPv6 - we bind to IPv6 socket, disable IPv6Only flag (doesn't work on Windows
-- < 7, OpenBSD?) and accept connections from both IPv4 and IPv6 peers (we
-- translate IPv4 address of a peer embedded as IPv6 address to its original
-- form). We store both IPv4 and IPv6 addresses in our routing table (each leaf
-- has two buckets, one for IPv6 and one for IPv4). When IPv4 peer sends us
-- FindNode request, we only return IPv4 peers. When IPv6 peer sends us FindNode
-- request, it also sends whether he wants to receive IPv4 addresses. If that's
-- the case, we return both for a certain bucket, prioritizing IPv6 peers over
-- IPv4 ones.
--
-- PROBLEM: requestAddress will return either our IPv4 address or IPv6.
--
-- IPv4 - we bind to IPv4 socket and store only IPv4 addresses in the routing
-- table (we keep empty buckets of IPv6 addresses for compatibility with IPv6
-- mode). A flag sent along with incoming FindNode requests about returning only
-- IPv6 hosts is ignored.
--
-- 2. Node id is required for the routing table - when we bootstrap, we need to
-- request from the first node we're contacting to send us our address as it
-- sees it. If we get the message on the given port, we're addressable and we
-- know of our id.
--
-- 3. Since we derive id from address info, we need to handle the situation in
-- which our address changes - we need to periodically request our address info
-- from nodes and if it differs from the one we know of, we rebuild our routing
-- table.
--
-- 4. No need to worry about splitting data into multiple packets - as we don't
-- send ids, we can pack a list of 50 CBOR encoded node addresses in 500 bytes.

-- | Start multiple peer discovery instances.
withPeerDiscoveries
  :: Config
  -> [(Maybe HostName, PortNumber)]
  -> ([PeerDiscovery] -> IO r)
  -> IO r
withPeerDiscoveries conf connInfos k = go [] connInfos
  where
    go acc = \case
      []                   -> k (reverse acc)
      ((mhost, port):rest) -> do
        withPeerDiscovery conf mhost port $ \pd -> go (pd : acc) rest

main :: IO ()
main = do
  let connInfos = map (Just "127.0.0.1", ) [3000..3200]
  withPeerDiscoveries defaultConfig connInfos $ \pds -> do

    let peers = let xs = map pdBindAddr pds in map (\x -> [x]) (last xs : init xs)
    zipWithM_ (\pd peer -> do
                  putStrLn $ "Bootstrapping " ++ show (pdBindAddr pd)
                  bootstrap True pd peer
              ) pds peers

    let pd1 = head pds
        pd2 = pds !! 100
    pPrint =<< readMVar (pdRoutingTable pd1)
    pPrint =<< peerLookup pd1 (mkPeerId $ pdBindAddr pd2)
