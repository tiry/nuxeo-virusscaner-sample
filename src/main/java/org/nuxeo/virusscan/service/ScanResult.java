package org.nuxeo.virusscan.service;

public class ScanResult {

    protected final boolean virusDetected ;

    protected final String scanInfo;

    protected final boolean error;

    public ScanResult (boolean virusDetected, String scanInfo) {
        this.virusDetected=virusDetected;
        this.scanInfo=scanInfo;
        this.error=false;
    }

    private ScanResult (String scanInfo) {
        this.virusDetected=false;
        this.scanInfo=scanInfo;
        this.error=true;
    }

    public static ScanResult makeFailed(String message) {
        return new ScanResult(message);
    }

    public boolean isVirusDetected() {
        return virusDetected;
    }

    public String getScanInfo() {
        return scanInfo;
    }

    public boolean isError() {
        return error;
    }




}
