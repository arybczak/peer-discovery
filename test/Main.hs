module Main where

import Control.Concurrent
import Control.Monad
import Network.Socket
import Text.Pretty.Simple
import System.Random
import qualified Data.ByteString as BS
import qualified Crypto.Error as C
import qualified Crypto.PubKey.Ed25519 as C

import Network.PeerDiscovery
import Network.PeerDiscovery.Operations
import Network.PeerDiscovery.Types

-- | Notes
--
-- TODO:
--
-- - Thread for periodically refreshing routing table (calling peer lookup)
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
-- IPv4 - we bind to IPv4 socket and store only IPv4 addresses in the routing
-- table (we keep empty buckets of IPv6 addresses for compatibility with IPv6
-- mode). A flag sent along with incoming FindNode requests about returning only
-- IPv6 hosts is ignored.
--
-- 2. We should support persistent key pairs. This way, for "central" instances
-- new nodes will boostrap their instances with, we can publish their key
-- fingerprints along with ip addresses / domain names, so that when we
-- bootstrap, we can use them to verify the authenticity of hosts we connect to.
--
-- 4. No need to worry about splitting data into multiple packets - for bucket
-- size of 10 ReturnNodes message takes less than 500 bytes. If we want to use
-- larger bucket size (which most likely is not needed as bucket size represents
-- redundancy and 10 is fine) it's fine up to 35 (~1430 bytes, Ethernet MTU is
-- 1500, 1472 for IPv4 and 1452 for IPv6 without appropriate headers).

-- | Start multiple peer discovery instances.
withPeerDiscoveries
  :: Config
  -> [(Bool, Maybe HostName, PortNumber)]
  -> ([PeerDiscovery] -> IO r)
  -> IO r
withPeerDiscoveries conf connInfos k = go [] connInfos
  where
    go acc = \case
      []                                -> k (reverse acc)
      ((joinNetwork, mhost, port):rest) -> do
        let C.CryptoPassed skey = C.secretKey . BS.pack . take C.secretKeySize
                                . randoms . mkStdGen $ fromIntegral port
        withPeerDiscovery conf joinNetwork (Just skey) mhost port $ \pd ->
          go (pd : acc) rest

main :: IO ()
main = do
  let connInfos = map (True, Just "127.0.0.1", ) [3000..3500]
  withPeerDiscoveries defaultConfig connInfos $ \pds -> do

    let nodes = let xs = map (\pd -> Node { nodeId = mkPeerId $ pdPublicKey pd
                                          , nodePeer = pdBindAddr pd
                                          }) pds
                in last xs : init xs
    zipWithM_ (\pd node -> do
                  putStrLn $ "Bootstrapping " ++ show (pdBindAddr pd)
                  bootstrap pd node
              ) pds nodes

    forM_ pds $ \pd -> void $ peerLookup pd =<< randomPeerId
    --forM_ pds $ \pd -> void $ peerLookup pd =<< randomPeerId

    let pd1 = head pds
        pd2 = pds !! 250
    pPrint =<< readMVar (pdRoutingTable pd1)
    let targetId = mkPeerId $ pdPublicKey pd2
    pPrint . map (\x -> let d = distance targetId (nodeId x) in (length (show d), d, x))
      =<< peerLookup pd1 targetId
