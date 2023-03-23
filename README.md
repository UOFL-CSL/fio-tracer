# fio-tracer experiment

## How do I benchmark the kernel?

In attempting to benchmark the performance of a device and isolate software and hardware latencies across different layers of the linux kernel, it is important to be able to strategically insert tracepoints. Details on this procedure can be found in the following very informative articles:
- https://lwn.net/Articles/379903/
- https://lwn.net/Articles/381064/
- https://lwn.net/Articles/383362/

## Existing Tool: fio-tracer

Although arbitrary tracepoints can be inserted in the linux kernel to garner quite a bit of information (and then ftrace/trace-cmd can be utilized in conjunction with a variety of scripts to automate the leveraging of said tracepoints), a simple method of logging latencies across the software stack is by utilizing blktrace's existing interface for aggregating and parsing existing tracepoints. Such an implemetation has already been written by Jared: https://github.com/UOFL-CSL/fio-tracer.

Unfortunately, this implementation makes use of several antiquated components. For starters, the code is written for older versions of the linux kernel (4.18), fio, blktrace, and python. This causes compatibiilty problems with existing APIs and data generated.

Thus, a modified version (with rudimentary configuration files) has been provided that is meant to work with the following:
- Python 3.10.6 and the packages detailed in requirements.txt
- fio 3.31-8-g7a7bc
- blktrace 2.0.0
- modified 5.18.19 linux kernel

To start with the explanation of this utility, it is necessary to detail the types of actions it attempts to record. As mentioned, the utility uses blktrace's interface, and thus uses its actions. These, with their relevant tracepoints, are as follows:
- Q - Queue (trace_block_bio_queue)
- D - Issue (trace_block_rq_issue)
- S - Sleep requests (trace_block_sleeprq)
- C - Complete (trace_block_bio_complete, trace_block_rq_complete)

If an individual were curious about the specific placements of these tracepoints they could run the following command:
`grep -RPIn "trace_block_(bio|rq|sleeprq)(_(complete|issue|queue)|)(\s|\(|;|$)"`

On the modified kernel (modified version of 5.18.19) used for this exerpiment, this would roughly yield they following output:
```
block/bio.c:1502:		trace_block_bio_complete(bdev_get_queue(bio->bi_bdev), bio);
block/blk-mq.c:727:	trace_block_rq_complete(req, BLK_STS_OK, total_bytes);
block/blk-mq.c:789:	trace_block_rq_complete(req, error, nr_bytes);
block/blk-mq.c:1135:	trace_block_rq_issue(rq);
block/blk-core.c:845:		trace_block_bio_queue(bio);
drivers/nvme/host/nvme.h:823:		trace_block_bio_complete(ns->head->disk->queue, req->bio);
drivers/nvme/host/pci.c:973:	trace_block_sleeprq(req->q, req->bio, 0);
drivers/nvme/host/pci.c:1026:			trace_block_sleeprq(req->q, req->bio, 0);
kernel/trace/blktrace.c:1116:	ret = register_trace_block_rq_issue(blk_add_trace_rq_issue, NULL);
kernel/trace/blktrace.c:1122:	ret = register_trace_block_rq_complete(blk_add_trace_rq_complete, NULL);
kernel/trace/blktrace.c:1126:	ret = register_trace_block_bio_complete(blk_add_trace_bio_complete, NULL);
kernel/trace/blktrace.c:1132:	ret = register_trace_block_bio_queue(blk_add_trace_bio_queue, NULL);
kernel/trace/blktrace.c:1136:	ret = register_trace_block_sleeprq(blk_add_trace_sleeprq, NULL);
kernel/trace/blktrace.c:1157:	unregister_trace_block_sleeprq(blk_add_trace_sleeprq, NULL);
kernel/trace/blktrace.c:1159:	unregister_trace_block_bio_queue(blk_add_trace_bio_queue, NULL);
kernel/trace/blktrace.c:1162:	unregister_trace_block_bio_complete(blk_add_trace_bio_complete, NULL);
kernel/trace/blktrace.c:1164:	unregister_trace_block_rq_complete(blk_add_trace_rq_complete, NULL);
kernel/trace/blktrace.c:1167:	unregister_trace_block_rq_issue(blk_add_trace_rq_issue, NULL);
```

Observably, quite a bit of the obtained code from this search is dedicated to mapping tracepoints to their relevant action types in blktrace. With that being said, unfortunately, in 4.18 the `trace_block_sleeprq` tracepoint was unused and has since been deprecated and removed from the kernel (https://github.com/torvalds/linux/commit/b81b8f40c5b43dcb2ff473236baccc421706435f). Although this is the case, its relevant ation type still exists within blktrace.

When Jared created the original utility, this tracepoint and action type represented an ideal candidate for adding granularity to the trace being performed by blktrace. Then, a simple addition of this tracepoint in the kernel would allow for an additional point of measurement. For simplicity's sake and to maintain continuity, this tracepoint was added back into the kernel for this experiment.

Some additional explanation of the utility is still required to understand its output. Specifically, these are in the form of the metrics that it reports. Most basically, these are as follows:
- CLAT (Completion Latency) [µs] : (source) fio
- SLAT (Submission Latency) [µs] : (source) fio
- Q2C (Request latency) [µs] : (source) blktrace (C - Q)
- Q2D (Block Layer Latency) [µs] : (source) blktrace (D - Q)
- D2S (Driver Latency) [µs] : (source) blktrace (S - D)
- S2C (Device Latency) [µs] : (source) blktrace (C - S)
- fs (File System Latency) [µs] : (source) fio/blktrace (clat - (slat + Q2C))

A final note of importance is the calculation of `fs`. In the original utility written by Jared, `fs` was calculated via `CLAT - Q2C` and documented as `SLAT - Q2C`. Unfortunately, both calculations do not account for the entire completion latency and any estimation of the filesystem based on the obtained data combines information directly traced via the kernel (blktrace) and estimations taken from application space (fio).

### IMPORTANT
The utility provided for this experiment reports negative values because of this. I thought it more valuable to include a more correct formula then report a value that looks better but was likely incorrect. For the purposes of this experiment, the time taken in the filesystem cannot be accurately measured.

## The limitations

The biggest disadvantage of this technique is the use of blktrace. Although blkrace provides a nice interface for tracking specific requests, by uisng blktrace an individual is limiting themselves to the use of the actions and tracepoints provided by blktrace. For this experiment, the `S` action was modified to add an additional point of measurement, but this does not guarantee scalability. Assuming an arbitrarily large amount of desired information and granularity, blktrace would not be able to support such a requirement.

In addition to this, this utility mixes data obtained by fio and blktrace (in the fs measurement). This is potentially dangerous, especially if fio does not make use of tracepoints and makes estimations itself. This could create misinterpretations of the results and especially in conclusions related to the filesystem timing.

It would be more advantageous to determine exactly what points in the kernel demarc transitions between layers and add tracepoints manually, then leverage these tracepoints via ftrace/trace-cmd directly. This would guarantee the reliability of the obtained latencies and data and would allow for scalability.

The limitations of this are, of course, an individual's understanding of the underlying code of the actions they are trying to track in the kernel. Useful utilities to determine placements of tracepoints include qemu/libvirt, gdb, grep, cscope, and ftrace/trace-cmd.

Another disadvantage of this utility is that it requires the use of an asynchronous ioengine. This is because it expects a tangible submission latency. Although useful, this does not allow for a direct comparison between polling vs. interrupts.

## The results

The goal of this experiment was to demonstrate the time taken in various layers of the storage stack of the kernel. This was being done from the lens of efficiency of polling vs. interrupts.  

## The takeaway

The events generated from this utility attempt to estimate the time taken in different layers of the kernel's storage stack in accordance with the placement of existing tracepoints. Although this is the case, this experiment is valuable because it details the necessary steps to set up any tracepoint in the kernel, capture arbitrary data from running processes in the kernel, and create a detailed performance breakdown of any desired actions in the kernel.
	
