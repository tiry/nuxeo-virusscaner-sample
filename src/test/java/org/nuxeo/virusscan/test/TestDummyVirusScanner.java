package org.nuxeo.virusscan.test;

import java.io.Serializable;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.impl.blob.StringBlob;
import org.nuxeo.ecm.core.event.EventService;
import org.nuxeo.ecm.core.test.TransactionalFeature;
import org.nuxeo.ecm.core.test.annotations.TransactionalConfig;
import org.nuxeo.ecm.core.work.api.WorkManager;
import org.nuxeo.ecm.platform.test.PlatformFeature;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.transaction.TransactionHelper;
import org.nuxeo.virusscan.VirusScanConsts;
import org.nuxeo.virusscan.service.DummyVirusScanner;

import com.google.inject.Inject;

@RunWith(FeaturesRunner.class)
@Features({ TransactionalFeature.class, PlatformFeature.class })
@TransactionalConfig(autoStart = false)
@Deploy({ "org.nuxeo.ecm.core.event", "org.nuxeo.virusscaner" })
public class TestDummyVirusScanner {

    @Inject
    protected CoreSession session;

    @Inject
    protected EventService eventService;

    @Inject
    WorkManager workManager;

    protected Blob getFakeBlob(int size, String name) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append('a');
        }
        Blob blob = new StringBlob(sb.toString());
        blob.setMimeType("text/plain");
        blob.setFilename(name);
        return blob;
    }


    @Test
    public void testScanner() throws Exception {

        DocumentModel file;
        DocumentModel file2;

        TransactionHelper.startTransaction();
        try {
            file = session.createDocumentModel("/", "file1",
                    "File");
            file.setPropertyValue("file:content", (Serializable) getFakeBlob(100, "Test1.txt"));
            file = session.createDocument(file);

            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        TransactionHelper.startTransaction();
        try {
            file2 = session.createDocumentModel("/", "file2",
                    "File");
            file2 = session.createDocument(file2);
            session.save();

            file2.setPropertyValue("file:content", (Serializable) getFakeBlob(1001, "Test2.txt"));
            file2 = session.saveDocument(file2);
            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        //Thread.sleep(4000);

        //eventService.waitForAsyncCompletion(4000);
        workManager.awaitCompletion(10, TimeUnit.SECONDS);

        List<String> scannedFiles = DummyVirusScanner.getProcessedFiles();

        Assert.assertTrue(scannedFiles.contains("Test1.txt"));
        Assert.assertTrue(scannedFiles.contains("Test2.txt"));


        session.save();
        TransactionHelper.startTransaction();
        try {

            file = session.getDocument(file.getRef());
            file2 = session.getDocument(file2.getRef());

            Assert.assertTrue(file.hasFacet(VirusScanConsts.VIRUSSCAN_FACET));
            Assert.assertTrue(file2.hasFacet(VirusScanConsts.VIRUSSCAN_FACET));

            //Assert.assertTrue((Boolean)file.getPropertyValue(VirusScanConsts.VIRUSSCAN_OK_PROP));
            //Assert.assertTrue((Boolean)file2.getPropertyValue(VirusScanConsts.VIRUSSCAN_OK_PROP));

            //Assert.assertEquals(VirusScanConsts.VIRUSSCAN_STATUS_DONE,file.getPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP));
            //Assert.assertEquals(VirusScanConsts.VIRUSSCAN_STATUS_DONE,file2.getPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP));

        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }


        System.out.println(DummyVirusScanner.getProcessedFiles());

    }


}
