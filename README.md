nuxeo-virusscaner-sample
========================

A sample Nuxeo plugin to demonstrate a simple integration of a VirusScaner

## Principles

This sample plugin try to demonstrate how Nuxeo infrastructure can be used to handle a potential long running and expensive processing that should be event driven.

Here the example is a VirusScaner, but this could be the same for a lot of similar processings :

 - OCR
 - digital sigature
 - calling a WS
 - ...

The principles demonstrated here are :

 - coupling of Sync Listener + AsynListener
    - the Sync listener gather the info based on Dirty Fields
    - the Async listener does the heavy lifting
 - avoid recentrency
    - Async lister uses a Flag in Context map to avoid reentrency in Sync Listener
 - use of `BlobsExtractor` to extract the Blobs
 - using  `AbstractLongRunningListener` to split the long running processing into 3 sub parts 
    1. transactional short preprocessing
    1. long processing outside of transactional context
    1. transactional short postprocessing
	
## About VirusScanner

The current implementation of `ScanService` is just for testing purpose, it does nothing.	

You should be able to take example on the existing code to build your own ScanService implementation.

## About Facet and VirsuScanner

The `VIRUSSCAN` facet is added to documents and provide information about VirusScan process :

 - flag to indicate that Document is virus free  or not
 - note about the potential infested files if any
 - flag about virusscan process (pending, in progress, done, failed)


