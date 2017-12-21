/*
 * Mosh support Copyright 2012 Daniel Drown
 *
 * Code based on ConnectBot's SSH client
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.codepunks.moshbot.transport;

import java.io.IOException;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;

import org.codepunks.moshbot.bean.HostBean;
import org.codepunks.moshbot.service.TerminalBridge;
import org.codepunks.moshbot.service.TerminalManager;
import org.codepunks.moshbot.util.InstallMosh;

import android.util.Log;

import com.trilead.ssh2.AuthAgentCallback;
import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.ConnectionMonitor;
import com.trilead.ssh2.InteractiveCallback;
import com.trilead.ssh2.ServerHostKeyVerifier;

import com.google.ase.Exec;

public class Mosh extends SSH implements ConnectionMonitor, InteractiveCallback, AuthAgentCallback {
	private String moshPort, moshKey, moshIP;
	private boolean sshDone = false;
	private Integer moshPid;

	private FileDescriptor shellFd;

	private FileInputStream is;
	private FileOutputStream os;

	public static final String PROTOCOL = "mosh";
	private static final String TAG = "CB.MOSH";
	private static final int DEFAULT_PORT = 22;

	private boolean stoppedForBackground = false;

	public Mosh() {
		super();
	}

	/**
	 * @param bridge
	 * @param db
	 */
	public Mosh(HostBean host, TerminalBridge bridge, TerminalManager manager) {
		super(host, bridge, manager);
	}

	@Override
	public void close() {
		try {
			if (os != null) {
				os.close();
				os = null;
			}
			if (is != null) {
				is.close();
				is = null;
			}
		} catch (IOException e) {
			Log.e(TAG, "Couldn't close mosh", e);
		}

		if (connected)
			super.close();

		if (moshPid != null) {
			synchronized (moshPid) { 
				if (moshPid > 0) {
					Exec.kill(moshPid, 18); // SIGCONT in case it's stopped
					Exec.kill(moshPid, 15); // SIGTERM
				}
			}
		}
	}

	public void onBackground() {
		if (sshDone) {
			synchronized (moshPid) {
				if (moshPid > 0)
					Exec.kill(moshPid, 19); // SIGSTOP
				stoppedForBackground = true;
			}
		}
	}

	public void onForeground() {
		if (sshDone) {
			synchronized (moshPid) {
				if (moshPid > 0)
					Exec.kill(moshPid, 18); // SIGCONT
				stoppedForBackground = false;
			}
		}
	}

	public void onScreenOff() {
		if (sshDone) {
			synchronized (moshPid) {
				if (moshPid > 0 && !stoppedForBackground)
					Exec.kill(moshPid, 19); // SIGSTOP
			}
		}
	}

	public void onScreenOn() {
		if (sshDone) {
			synchronized (moshPid) {
				if (moshPid > 0 && !stoppedForBackground)
					Exec.kill(moshPid, 18); // SIGCONT
			}
		}
	}

	/**
	 * Internal method to request actual PTY terminal once we've finished
	 * authentication. If called before authenticated, it will just fail.
	 */
	@Override
	protected void finishConnection() {
		authenticated = true;

		try {
			bridge.outputLine("trying to run mosh-server on the remote server");
			session = connection.openSession();

			session.requestPTY("screen", 80, 25, 800, 600, null);
			// FIXME: Wont compile without hacking the ssh lib
			// try {
			//	 session.sendEnvironment("LANG",host.getLocale());
			// } catch(IOException e) {
			//	 bridge.outputLine("ssh rejected our LANG environment variable: " + e.getMessage());
			// }

			String serverCommand = host.getMoshServer();
			if (serverCommand == null) {
				serverCommand = "mosh-server";
			}
			serverCommand += " new -s -l LANG=" + host.getLocale();
			if (host.getMoshPort() > 0) {
				serverCommand += " -p " + host.getMoshPort();
			}
			session.execCommand(serverCommand);

			stdin = session.getStdin();
			stdout = session.getStdout();
			stderr = session.getStderr();

			// means SSH session
			sessionOpen = true;

			bridge.onConnected(false);
		} catch (IOException e1) {
			Log.e(TAG, "Problem while trying to create PTY in finishConnection()", e1);
		}
	}

	// use this class to pass the actual hostname to the actual HostKeyVerifier, otherwise it gets the raw IP
	public class MoshHostKeyVerifier extends HostKeyVerifier implements ServerHostKeyVerifier {
		String realHostname;
		public MoshHostKeyVerifier(String hostname) {
			realHostname = hostname;
		}
	
		public boolean verifyServerHostKey(
			String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException {
			return super.verifyServerHostKey(realHostname, port, serverHostKeyAlgorithm, serverHostKey);
		}
	}

	@Override
	public void connect() {
		if (!InstallMosh.isInstallStarted()) {
			// check that InstallMosh was called by the Activity
			bridge.outputLine("mosh-client binary install not started");
			onDisconnect();
			return;
		}
		if (!InstallMosh.isInstallDone()) {
			bridge.outputLine("waiting for mosh binaries to install");
			InstallMosh.waitForInstall();
		}
				
		if (!InstallMosh.getMoshInstallStatus()) {
			bridge.outputLine("mosh-client binary not found; install process failed");
			bridge.outputLine(InstallMosh.getInstallMessages());
			onDisconnect();
			return;
		}
				
		bridge.outputLine(InstallMosh.getInstallMessages());
				
		InetAddress addresses[];
		try {
			addresses = InetAddress.getAllByName(host.getHostname());
		} catch (UnknownHostException e) {
			bridge.outputLine("Launching mosh server via SSH failed, Unknown hostname: " + host.getHostname());
			
			onDisconnect();
			return;
		}
		
		moshIP = null;
		int try_family = 4;
		for (int i = 0; i < addresses.length || try_family == 4; i++) {
			if (i == addresses.length) {
				i = 0;
				try_family = 6;
			}
			if (addresses.length == 0) {
				break;
			}
			if (try_family == 4 && addresses[i] instanceof Inet4Address) {
				moshIP = addresses[i].getHostAddress();
				break;
			}
			if (try_family == 6 && addresses[i] instanceof Inet6Address) {
				moshIP = addresses[i].getHostAddress();
				break;
			}
		}
		if (moshIP == null) {
			bridge.outputLine("No address records found for hostname: " + host.getHostname());
			
			onDisconnect();
			return;
		}
		bridge.outputLine("Mosh IP = " + moshIP);

		super.connect();
	}

	@Override
	public String instanceProtocolName() {
		return PROTOCOL;
	}

	public static String getProtocolName() {
		return PROTOCOL;
	}

	@Override
	public String getDefaultNickname(String username, String hostname, int port) {
		if (port == DEFAULT_PORT) {
			return String.format("mosh %s@%s", username, hostname);
		} else {
			return String.format("mosh %s@%s:%d", username, hostname, port);
		}
	}

	@Override
	public void flush() throws IOException {
		if (sshDone) {
			os.flush();
		} else {
			super.flush();
		}
	}

	@Override
	public boolean isConnected() {
		if (sshDone) {
			return is != null && os != null;
		} else {
			return super.isConnected();
		}
	}

	@Override
	public void connectionLost(Throwable reason) {
		if (!sshDone)
			onDisconnect();
	}

	@Override
	public boolean isSessionOpen() {
		if (sshDone) {
			return is != null && os != null;
		} else {
			return super.isSessionOpen();
		}
	}

	private void launchMosh() {
		int[] pids = new int[1];

		Exec.setenv("MOSH_KEY", moshKey);
		Exec.setenv("TERM", getEmulation());
		try {
			shellFd = Exec.createSubprocess(InstallMosh.getMoshPath(), moshIP, moshPort, pids);
			Exec.setPtyWindowSize(shellFd, rows, columns, width, height);
		} catch (Exception e) {
			bridge.outputLine("failed to start mosh-client: " + e.toString());
			Log.e(TAG, "Cannot start mosh-client", e);
			onDisconnect();
			return;
		} finally {
			Exec.setenv("MOSH_KEY", "");
		}
		
		moshPid = pids[0];
		Runnable exitWatcher = new Runnable() {
				public void run() {
					Exec.waitFor(moshPid);
					synchronized (moshPid) { 
						moshPid = 0;
					};
					
					bridge.dispatchDisconnect(false);
				}
			};

		Thread exitWatcherThread = new Thread(exitWatcher);
		exitWatcherThread.setName("LocalExitWatcher");
		exitWatcherThread.setDaemon(true);
		exitWatcherThread.start();

		is = new FileInputStream(shellFd);
		os = new FileOutputStream(shellFd);
		
		bridge.postLogin();
	}
	
	@Override
	public int read(byte[] buffer, int start, int len) throws IOException {
		if (sshDone) {
			return mosh_read(buffer, start, len);
		} else {
			return ssh_read(buffer, start, len);
		}
	}

	private int mosh_read(byte[] buffer, int start, int len) throws IOException {
		if (is == null) {
			bridge.dispatchDisconnect(false);
			throw new IOException("session closed");
		}
		return is.read(buffer, start, len);
	}

	private int ssh_read(byte[] buffer, int start, int len) throws IOException {
		int bytesRead = 0;

		if (session == null)
			return 0;

		int newConditions = session.waitForCondition(conditions, 0);

		if ((newConditions & ChannelCondition.STDOUT_DATA) != 0) {
			bytesRead = stdout.read(buffer, start, len);
			String data = new String(buffer);
			int connectOffset = data.indexOf("MOSH CONNECT");

			if (connectOffset > -1) {
				int end = data.indexOf(" ", connectOffset + 13);
				if (end > -1) {
					moshPort = data.substring(connectOffset + 13, end);
					int keyEnd = data.indexOf("\n", end + 1);
					if (keyEnd > -1) {
						moshKey = data.substring(end + 1, keyEnd - 1);
						sshDone = true;
						launchMosh();
					}
				}
			}
		}

		if ((newConditions & ChannelCondition.STDERR_DATA) != 0) {
			byte discard[] = new byte[256];
			while (stderr.available() > 0) {
				stderr.read(discard);
			}
		}

		if ((newConditions & ChannelCondition.EOF) != 0) {
			if (!sshDone) {
				onDisconnect();
				throw new IOException("Remote end closed connection");
			}
		}

		return bytesRead;
	}

	@Override
	public void setDimensions(int columns, int rows, int width, int height) {
		if (sshDone) {
			try {
				Exec.setPtyWindowSize(shellFd, rows, columns, width, height);
			} catch (Exception e) {
				Log.e(TAG, "Couldn't resize pty", e);
			}
		} else {
			super.setDimensions(columns, rows, width, height);
		}
	}

	@Override
	public void write(byte[] buffer) throws IOException {
		if (sshDone) {
			if (os != null)
				os.write(buffer);
		} else {
			super.write(buffer);
		}
	}

	@Override
	public void write(int c) throws IOException {
		if (sshDone) {
			if (os != null)
				os.write(c);
		} else {
			super.write(c);
		}
	}

	@Override
	public boolean canForwardPorts() {
		return false;
	}

	@Override
	public boolean usesNetwork() {
		return false; // don't hold wifilock
	}

	@Override
	public boolean resetOnConnectionChange() {
		return false;
	}
}
