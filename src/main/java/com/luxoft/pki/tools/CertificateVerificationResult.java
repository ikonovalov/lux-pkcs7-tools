package com.luxoft.pki.tools;

import java.security.cert.CertPathValidatorResult;
import java.security.cert.PKIXCertPathBuilderResult;

/**
 * This class keeps the result from the certificate verification process. If the
 * the certificate is verified as valid, the built certification chain is stored
 * in the Result property. If the certificate is invalid, the problem is stored
 * in the Exception property.
 * 
 * @author Svetlin Nakov
 */
public class CertificateVerificationResult {
	private boolean valid;
	private PKIXCertPathBuilderResult buildpathResult;
	private CertPathValidatorResult validationResult;
	private Throwable exception;

	/**
	 * Constructs a certificate verification result for valid certificate by
	 * given certification path.
	 */
	public CertificateVerificationResult(PKIXCertPathBuilderResult result, CertPathValidatorResult validationResult) {
		this.valid = true;
		this.buildpathResult = result;
		this.validationResult = validationResult;
	}

	/**
	 * Constructs a certificate verification result for invalid certificate by
	 * given exception that keeps the problem occurred during the verification
	 * process.
	 */
	public CertificateVerificationResult(Throwable exception) {
		this.valid = false;
		this.exception = exception;
	}

	public final boolean isValid() {
		return valid;
	}

	public final PKIXCertPathBuilderResult getBuildPathResult() {
		return buildpathResult;
	}
	
	public final CertPathValidatorResult getValidationResult() {
		return validationResult;
	}

	public final Throwable getException() {
		return exception;
	}

	@Override
	public String toString() {
		if (valid) {
			return buildpathResult.toString();
		} else {
			return exception.getMessage();
		}
	}
	
	
}