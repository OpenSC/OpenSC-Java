/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.opensc.pkcs15;

import javax.smartcardio.CardException;

/**
 *
 * @author hfman
 */
public class PKCS15CardException extends PKCS15Exception{
    public PKCS15CardException(String msg, CardException cause) {
        super(msg, cause);
    }
}
