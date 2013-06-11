package org.nuxeo.virusscan.service;

import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.ClientException;

public interface ScanService {

    ScanResult scanBlob(Blob blob) throws ClientException;

}
