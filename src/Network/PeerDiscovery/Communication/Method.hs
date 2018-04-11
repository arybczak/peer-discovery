{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE RankNTypes #-}
module Network.PeerDiscovery.Communication.Method
  ( CommunicationMethod
  , UdpSocket
  , udpSocket
  , StmRouter
  , stmRouter
  , withStmRouter
  ) where

import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Exception
import Control.Monad
import Data.Function
import Network.Socket hiding (recvFrom, sendTo)
import qualified Data.Map.Strict as M
import qualified Network.Socket.ByteString as S

import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

type CommunicationMethod cm
   = forall r. PortNumber
  -> (Peer -> CommInterface -> IO r)
  -> IO r

data UdpSocket

-- | Construct communication method based on UDP sockets.
udpSocket
  :: Maybe HostName -- ^ Host name to bind to, if applicable.
  -> CommunicationMethod UdpSocket
udpSocket mhost port k = do
  getAddrInfo (Just hints) mhost (Just $ show port) >>= \case
    []   -> error $ "udpSocket: couldn't create IPv4 UDP socket on port "
                 ++ show port
    (ai:_) -> case mkPeer (addrAddress ai) of
      Nothing -> error $ "udpSocket: couldn't create Peer from "
                      ++ show (addrAddress ai)
      Just peer -> do
        sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
        bracket_ (bind sock (addrAddress ai)) (close sock) $
          k peer $ CommInterface { recvFrom = recvFromImpl sock
                                 , sendTo   = sendToImpl sock
                                 }
  where
    hints = defaultHints { addrFamily = AF_INET
                         , addrFlags = [AI_PASSIVE]
                         , addrSocketType = Datagram
                         }

    recvFromImpl sock = fix $ \loop -> do
      (bytes, source) <- S.recvFrom sock 4096
      case mkPeer source of
        Nothing -> do
          putStrLn $ "recvFrom: couldn't construct Peer from " ++ show source
          loop
        Just peer -> case deserialiseOrFail' bytes of
          Right signal -> return (peer, signal)
          Left err -> do
            putStrLn $ "recvFrom: error while parsing signal: " ++ show err
            loop

    sendToImpl sock = \Peer{..} signal -> void $
      S.sendTo sock (serialise' signal) (SockAddrInet peerPort peerAddress)

----------------------------------------

-- | STM-based router for testing purposes.
data StmRouter = StmRouter
  { routerIncoming :: !(TQueue IncomingMsg)
  , routerOutgoing :: !(TVar (M.Map Peer (TQueue (Peer, Signal))))
  }

data IncomingMsg = IncomingMsg
  { msgSignal :: !Signal
  , msgSource :: !Peer
  , msgDest   :: !Peer
  }

-- | Construct new 'StmRouter' for use in the continuation.
withStmRouter :: (StmRouter -> IO r) -> IO r
withStmRouter k = do
  router <- StmRouter <$> newTQueueIO <*> newTVarIO M.empty
  withAsync (doRouting router) $ \_ -> k router
  where
    doRouting StmRouter{..} = fix $ \loop -> join . atomically $ do
      IncomingMsg{..} <- readTQueue routerIncoming
      routes <- readTVar routerOutgoing
      case msgDest `M.lookup` routes of
        Just route -> do
          writeTQueue route (msgSource, msgSignal)
          return loop
        Nothing -> return $ do
          putStrLn $ "doRouting: no route to " ++ show msgDest
                  ++ ", discarding message"
          loop

-- | Construct communication method based on 'StmRouter'.
stmRouter :: StmRouter -> CommunicationMethod StmRouter
stmRouter StmRouter{..} port k = bracket register unregister $ \route ->
  k peer $ CommInterface
    { recvFrom = atomically $ readTQueue route
    , sendTo   = \dest signal -> atomically $ do
        writeTQueue routerIncoming $ IncomingMsg { msgSignal = signal
                                                 , msgSource = peer
                                                 , msgDest   = dest
                                                 }
    }
  where
    peer = Peer 0 port

    register = atomically $ do
      routes <- readTVar routerOutgoing
      if peer `M.member` routes
        then error $ "register: route to " ++ show peer ++ " already exists"
        else do
          route <- newTQueue
          writeTVar routerOutgoing $! M.insert peer route routes
          return route

    unregister route = join . atomically $ do
      routes <- readTVar routerOutgoing
      case peer `M.lookup` routes of
        Nothing -> return . putStrLn $ "unregister: no route to " ++ show peer
        Just route'
          | route == route' -> do
              writeTVar routerOutgoing $! M.delete peer routes
              return $ return ()
          | otherwise -> return $ do
              putStrLn $ "unregister: route to " ++ show peer
                      ++ " is different than expected"
