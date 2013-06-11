package org.nuxeo.virusscan.test;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

/**
 * Test Blob scanning in standard use cases
 *
 * @author <a href="mailto:tdelprat@nuxeo.com">Tiry</a>
 *
 */
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
        DocumentModel file3;
        DocumentModel file4;

        TransactionHelper.startTransaction();
        try {
            file = session.createDocumentModel("/", "file1", "File");
            file.setPropertyValue("file:content",
                    (Serializable) getFakeBlob(100, "Test1.txt"));
            file = session.createDocument(file);

            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        TransactionHelper.startTransaction();
        try {
            file2 = session.createDocumentModel("/", "file2", "File");
            file2 = session.createDocument(file2);
            session.save();

            file2.setPropertyValue("file:content",
                    (Serializable) getFakeBlob(1001, "Test2.txt"));
            file2 = session.saveDocument(file2);

            file3 = session.createDocumentModel("/", "file3", "File");
            file3.setPropertyValue("file:content",
                    (Serializable) getFakeBlob(100, "Test3doFail.txt"));
            file3 = session.createDocument(file3);

            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        TransactionHelper.startTransaction();
        try {
            file4 = session.createDocumentModel("/", "file4", "File");
            file4.setPropertyValue("file:content",
                    (Serializable) getFakeBlob(100, "Test4.txt"));
            file4 = session.createDocument(file4);
            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        TransactionHelper.startTransaction();
        try {

            List<Map<String, Serializable>> files = new ArrayList<Map<String, Serializable>>();

            for (int i = 0; i < 5; i++) {
                Map<String, Serializable> map = new HashMap<String, Serializable>();
                map.put("file",
                        (Serializable) getFakeBlob(100, "Test4-" + i + ".txt"));
                map.put("filename", "Test4-" + i + ".txt");
                files.add(map);
            }

            file4.setPropertyValue("files:files", (Serializable) files);
            file4 = session.saveDocument(file4);
            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        TransactionHelper.startTransaction();
        try {

            List<Map<String, Serializable>> files = (List<Map<String, Serializable>>) file4.getPropertyValue("files:files");

            Map<String, Serializable> map = new HashMap<String, Serializable>();
            map.put("file", (Serializable) getFakeBlob(100, "Test4-b.txt"));
            map.put("filename", "Test4-b.txt");
            files.add(map);
            file4.setPropertyValue("files:files", (Serializable) files);
            file4 = session.saveDocument(file4);
            session.save();
        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }

        // wait for processing to be done
        Thread.sleep(1000);
        // eventService.waitForAsyncCompletion(5000);
        workManager.awaitCompletion(10, TimeUnit.SECONDS);

        List<String> scannedFiles = DummyVirusScanner.getProcessedFiles();

        // System.out.println(DummyVirusScanner.getProcessedFiles());

        Assert.assertTrue(scannedFiles.contains("Test1.txt"));
        Assert.assertTrue(scannedFiles.contains("Test2.txt"));
        Assert.assertTrue(scannedFiles.contains("Test3doFail.txt"));
        Assert.assertTrue(scannedFiles.contains("Test4.txt"));

        for (int i = 0; i < 5; i++) {
            Assert.assertTrue(scannedFiles.contains("Test4-" + i + ".txt"));
        }

        Assert.assertTrue(scannedFiles.contains("Test4-b.txt"));

        session.save();

        TransactionHelper.startTransaction();
        try {

            file = session.getDocument(file.getRef());
            file2 = session.getDocument(file2.getRef());
            file3 = session.getDocument(file3.getRef());

            Assert.assertTrue(file.hasFacet(VirusScanConsts.VIRUSSCAN_FACET));
            Assert.assertTrue(file2.hasFacet(VirusScanConsts.VIRUSSCAN_FACET));
            Assert.assertTrue(file3.hasFacet(VirusScanConsts.VIRUSSCAN_FACET));

            Assert.assertTrue((Boolean) file.getPropertyValue(VirusScanConsts.VIRUSSCAN_OK_PROP));
            Assert.assertTrue((Boolean) file2.getPropertyValue(VirusScanConsts.VIRUSSCAN_OK_PROP));
            Assert.assertFalse((Boolean) file3.getPropertyValue(VirusScanConsts.VIRUSSCAN_OK_PROP));

            Assert.assertEquals(
                    VirusScanConsts.VIRUSSCAN_STATUS_DONE,
                    file.getPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP));
            Assert.assertEquals(
                    VirusScanConsts.VIRUSSCAN_STATUS_DONE,
                    file2.getPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP));
            Assert.assertEquals(
                    VirusScanConsts.VIRUSSCAN_STATUS_FAILED,
                    file3.getPropertyValue(VirusScanConsts.VIRUSSCAN_STATUS_PROP));

        } finally {
            TransactionHelper.commitOrRollbackTransaction();
        }
    }
}
