package org.nuxeo.virusscan.service;

import java.util.ArrayList;
import java.util.List;

import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.ClientException;

public class DummyVirusScanner implements ScanService {

    protected static List<String> doneFiles = new ArrayList<String>();

    @Override
    public ScanResult scanBlob(Blob blob) throws ClientException {
        if (blob!=null) {
            doneFiles.add(blob.getFilename());
            return new ScanResult(false, "No virus found in " + blob.getFilename());
        } else {
            return new ScanResult(false, "No file found");
        }
    }

    public static List<String> getProcessedFiles() {
        return doneFiles;
    }
}
