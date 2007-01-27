/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Aug 6, 2006
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 * 
 ***********************************************************/

package org.opensc.test.pkcs11;

import java.awt.Frame;
import java.awt.GraphicsConfiguration;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.TextField;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.opensc.pkcs11.PKCS11EventCallback;

/**
 * A class ,that allows to enter PINs on the command line.
 * 
 * @author wglas
 */
public class PINEntry implements CallbackHandler
{
	private Label label;
	private Label prompt;
	private PINListener listener;
	private TextField textField;
	
	static private class PINListener implements KeyListener, WindowListener
	{
		private boolean accepted = false;
		private boolean interacted = false;
		private Frame frame;
		
		PINListener(Frame frame)
		{
			this.frame=frame;
		}
		
		private synchronized void accept()
		{
			this.frame.setVisible(false);
			this.frame.dispose();
			this.accepted = true;
			this.interacted = true;
			this.notify();	
		}
		
		private synchronized void reject()
		{
			this.frame.setVisible(false);
			this.frame.dispose();
			this.accepted = false;
			this.interacted = true;
			this.notify();	
		}
		
		public void keyTyped(KeyEvent ke)
		{
			switch (ke.getKeyChar())
			{
			case 10:
				accept();
				break;
			case 27:
				reject();
				break;
			}
		}

		public void keyPressed(KeyEvent ke)
		{}

		public void keyReleased(KeyEvent ke)
		{}

		public synchronized boolean waitForUser()
		{
			try
			{
				if (!this.interacted)
					this.wait();
			} catch (InterruptedException e)
			{
				e.printStackTrace();
			}
			return this.accepted;
		}

		public void windowOpened(WindowEvent arg0)
		{}

		public void windowClosing(WindowEvent we)
		{
			reject();
		}

		public void windowClosed(WindowEvent we)
		{}

		public void windowIconified(WindowEvent arg0)
		{}

		public void windowDeiconified(WindowEvent arg0)
		{}

		public void windowActivated(WindowEvent arg0)
		{}

		public void windowDeactivated(WindowEvent arg0)
		{}
	}
	
	/**
	 * Contructs a PINEntry instance. 
	 */
	public PINEntry()
	{
		super();
		Frame frame = new Frame("PIN entry");
		
		frame.setLayout(new GridLayout(2,2));
		
		frame.add(new Label("Event:"));
		
		this.label = new Label("NO_EVENT");
		frame.add(this.label);
		
		this.prompt = new Label();
		frame.add(this.prompt);
		
		this.listener = new PINListener(frame);

		this.textField = new TextField();
		this.textField.setEchoChar('*');
		this.textField.addKeyListener(this.listener);
		frame.add(this.textField);
		frame.addWindowListener(this.listener);
		
		frame.pack();
		frame.setVisible(true);
		
		GraphicsConfiguration gc = frame.getGraphicsConfiguration();
		Rectangle r = gc.getBounds();
		Point p = new Point((r.width-frame.getWidth())/2,(r.height-frame.getHeight())/2);
		
		frame.setLocation(p);
	}

	/**
	 * Get a PIN from the user using a simple AWT window.
	 * 
	 * @param promptText The prompt shown to the user.
	 * @return The entered PIN, if the user pressed the return key.
	 * @throws IOException If the user presses escape or closes the window.
	 */
	public char [] getPIN (String promptText) throws IOException
	{
		this.prompt.setText(promptText);
		
		if (!this.listener.waitForUser())
			throw new IOException("The Password dialog has been interrupted by the user.");
		
		String pw = this.textField.getText();
		char pin[] = pw.toCharArray();
		return pin;
	}
	
	/* (non-Javadoc)
	 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
	 */
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException
	{
		for (Callback callback : callbacks)
		{
			if (callback instanceof PasswordCallback)
			{
				PasswordCallback pwCb = (PasswordCallback)callback;
				
				char pin[] = this.getPIN(pwCb.getPrompt());
				
				pwCb.setPassword(pin);
			}
			else if (callback instanceof PKCS11EventCallback)
			{
				PKCS11EventCallback evCb = (PKCS11EventCallback)callback;
				
				this.label.setText(evCb.toString());
			}
			else
				throw new UnsupportedCallbackException(callback,"Only PasswordCallback or PKCS11EventCallback is supported.");
			
		}
	}

}
