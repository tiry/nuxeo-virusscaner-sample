package org.nuxeo.virusscan;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.event.EventBundle;
import org.nuxeo.ecm.core.event.PostCommitEventListener;
import org.nuxeo.ecm.core.event.PostCommitFilteringEventListener;
import org.nuxeo.ecm.core.event.impl.ReconnectedEventBundleImpl;
import org.nuxeo.ecm.core.work.api.Work;
import org.nuxeo.runtime.transaction.TransactionHelper;

/**
 * Abstract class that helps building an Asynchronous listeners that will handle
 * a long running process.
 * <p/>
 * By default, {@link PostCommitEventListener} are executed in a {@link Work}
 * that will take care of starting/comitting the transaction.
 * <p/>
 * If the listener requires a long processing this will create long transactions
 * that are not good. To avoid this behavior, this base class split the
 * processing in 3 steps :
 * <ul>
 * <li>pre processing : transactional first step</li>
 * <li>long running : long running processing that should not require
 * transactional resources</li>
 * <li>post processing : transactional final step
 * </ul>
 * <p/>
 * To manage sharing between the 3 steps, a simple Map is provided.
 *
 * @author <a href="mailto:tdelprat@nuxeo.com">Tiry</a>
 *
 */
public abstract class AbstractLongRunningListener implements
        PostCommitFilteringEventListener {

    protected static final Log log = LogFactory.getLog(AbstractLongRunningListener.class);

    @Override
    public void handleEvent(EventBundle events) throws ClientException {

        Map<String, Object> data = new HashMap<String, Object>();

        if (events instanceof ReconnectedEventBundleImpl) {

            boolean doContinue = false;
            // do pre-processing and commit transaction
            try {
                doContinue = handleEventPreprocessing(
                        new ReconnectedEventBundleImpl(events), data);
            } catch (ClientException e) {
                log.error(
                        "Long Running listener canceled after failed execution of preprocessing",
                        e);
                throw e;
            } finally {
                TransactionHelper.commitOrRollbackTransaction();
            }
            if (!doContinue) {
                return;
            }

            // do main-processing in a non transactional context
            // a new CoreSession will be open by ReconnectedEventBundleImpl
            try {
                handleEventLongRunning(((ReconnectedEventBundleImpl) events).getEventNames(),
                        data);
            } catch (ClientException e) {
                log.error(
                        "Long Running listener canceled after failed execution of main run",
                        e);
                throw e;
            } finally {
                //
            }

            // do final-processing in a new transaction
            // a new CoreSession will be open by ReconnectedEventBundleImpl
            try {
                TransactionHelper.startTransaction();
                handleEventPostprocessing(
                        new ReconnectedEventBundleImpl(events), data);
            } catch (ClientException e) {
                log.error(
                        "Long Running listener canceled after failed execution of main run",
                        e);
                throw e;
            } finally {
                TransactionHelper.commitOrRollbackTransaction();
            }
        } else {
            log.error("Unable to execute long running listener, input EventBundle is not a ReconnectedEventBundle");
        }
    }

    /**
     * Handles first step of processing in a normal transactional way.
     *
     * @param events {@link EventBundle} received
     * @param data an empty map to store data to share data between steps.
     * @return true of processing should continue, false otherwise
     * @throws ClientExceptions
     */
    protected abstract boolean handleEventPreprocessing(EventBundle events,
            Map<String, Object> data) throws ClientException;

    /**
     * Will be executed in a non transactional context
     * <p/> Any acess to a CoreSession will generate WARN in the the logs.
     * <p/>  Documents passed with data should not be connected.
     *
     * @param eventNames list of event names
     * @param data an map that may have been filled by handleEventPreprocessing
     * @throws ClientException
     */
    protected abstract void handleEventLongRunning(List<String> eventNames,
            Map<String, Object> data) throws ClientException;

    /**
     * Finish processing in a dedicated Transaction
     *
     * @param events {@link EventBundle} received
     * @param data an map that may have been filled by handleEventPreprocessing and handleEventLongRunning
     * @throws ClientException
     */
    protected abstract void handleEventPostprocessing(EventBundle events,
            Map<String, Object> data) throws ClientException;

}
