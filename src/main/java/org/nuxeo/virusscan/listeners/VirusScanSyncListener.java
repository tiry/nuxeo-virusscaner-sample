package org.nuxeo.virusscan.listeners;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.event.DocumentEventTypes;
import org.nuxeo.ecm.core.api.model.Property;
import org.nuxeo.ecm.core.event.Event;
import org.nuxeo.ecm.core.event.EventListener;
import org.nuxeo.ecm.core.event.EventService;
import org.nuxeo.ecm.core.event.impl.DocumentEventContext;
import org.nuxeo.ecm.core.utils.BlobsExtractor;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.virusscan.VirusScanConsts;

public class VirusScanSyncListener implements EventListener {


    protected static final Log log = LogFactory.getLog(VirusScanSyncListener.class);

    @Override
    public void handleEvent(Event event) throws ClientException {


        if (event.getContext() instanceof DocumentEventContext) {
            DocumentEventContext docCtx = (DocumentEventContext) event.getContext();
            DocumentModel targetDoc = docCtx.getSourceDocument();

            List<String> propertiesPath = null;

            if (DocumentEventTypes.ABOUT_TO_CREATE.equals(event.getName())) {
                // add the facet before save
                addScanFacet(targetDoc);
            } else if (DocumentEventTypes.DOCUMENT_CREATED.equals(event.getName())) {
                // process Blobs now that document is created
                propertiesPath = getBlobsXPath(targetDoc, false);
            } else if (DocumentEventTypes.BEFORE_DOC_UPDATE.equals(event.getName())) {
                // process Blobs before update
                propertiesPath = getBlobsXPath(targetDoc, true);
                addScanFacet(targetDoc);
            }

            if (propertiesPath!=null && propertiesPath.size()>0) {
                VirusScanEventContext virusScanCtx = new VirusScanEventContext(docCtx, propertiesPath);

                EventService eventService = Framework.getLocalService(EventService.class);
                eventService.fireEvent(virusScanCtx.newVirusScanEvent());
            }
        }
    }

    protected void addScanFacet(DocumentModel doc) throws ClientException {
        if (!doc.hasFacet(VirusScanConsts.VIRUSSCAN_FACET)) {
            doc.addFacet(VirusScanConsts.VIRUSSCAN_FACET);
        }
        doc.setPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP, VirusScanConsts.VIRUSSCAN_STATUS_PENDING);
    }

    protected List<String> getBlobsXPath(DocumentModel doc, boolean onlyChangedBlob)
            throws ClientException {

        List<String> propertiesPath = new ArrayList<String>();
        BlobsExtractor extractor = new BlobsExtractor();

        try {
            List<Property> blobProperties = extractor.getBlobsProperties(doc);

            for (Property prop : blobProperties) {
                if (onlyChangedBlob) {
                    if ( prop.isDirty()) {
                        propertiesPath.add(prop.getPath());
                    }
                } else {
                    propertiesPath.add(prop.getPath());
                }
            }
        } catch (Exception e) {
            log.error("Error when scanning blobs from Document", e);
            throw new ClientException(e);
        }

        return propertiesPath;
    }


}
