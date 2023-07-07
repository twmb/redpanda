// Copyright 2022 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package txn

import (
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/config"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/kafka"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/out"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/twmb/franz-go/pkg/kadm"
)

func newAbortCommand(fs afero.Fs, p *config.Params) *cobra.Command {
	var (
		topic       string
		partition   int32
		startOffset int64
	)
	cmd := &cobra.Command{
		Use:   "abort",
		Short: "Abort an open transaction for a given partition",
		Long: `Abort an open transaction for a given partition.

This command aborts a single partition in a transaction, allowing the
last-stable-offset to advance for the partition. To be extra cautious, this
command only aborts one partition at a time. You can run this repeatedly to
abort all partitions that may be hanging in a single transaction.

You can find potentially hanging transactions with the find-hanging command.
`,

		Run: func(cmd *cobra.Command, txnIDs []string) {
			p, err := p.LoadVirtualProfile(fs)
			out.MaybeDie(err, "unable to load config: %v", err)

			adm, err := kafka.NewAdmin(fs, p)
			out.MaybeDie(err, "unable to initialize kafka client: %v", err)
			defer adm.Close()

			var s kadm.TopicsSet
			s.Add(topic, partition)
			producers, err := adm.DescribeProducers(cmd.Context(), s)
			out.HandleShardError("DescribeProducers", err)

			var hung kadm.DescribedProducer
			var found bool
			producers.EachProducer(func(p kadm.DescribedProducer) {
				if p.CurrentTxnStartOffset == startOffset {
					hung = p
					found = true
					return
				}
			})
			if !found {
				out.Die("unable to find a hung transaction at start offset %d for topic %s partition %d", startOffset, topic, partition)
			}

			resp, err := adm.WriteTxnMarkers(cmd.Context(), kadm.TxnMarkers{
				ProducerID:       hung.ProducerID,
				ProducerEpoch:    hung.ProducerEpoch,
				Commit:           false,
				CoordinatorEpoch: hung.CoordinatorEpoch,
				Topics:           s,
			})
			out.HandleShardError("WriteTxnMarkers", err)

			tw := out.NewTable("topic", "partition", "producer-id", "error")
			defer tw.Flush()
			resp.EachPartition(func(p kadm.TxnMarkersPartitionResponse) {
				tw.PrintStructFields(struct {
					Topic      string
					Partition  int32
					ProducerID int64
					Err        error
				}{p.Topic, p.Partition, p.ProducerID, p.Err})
			})
		},
	}
	cmd.Flags().StringVarP(&topic, "topic", "t", "", "Topic to abort a transaction for")
	cmd.Flags().Int32VarP(&partition, "partition", "p", -1, "Partition to abort a transaction for")
	cmd.Flags().Int64VarP(&startOffset, "start-offset", "o", -1, "Transaction start offset that the transaction you are aborting is hung at")
	cobra.MarkFlagRequired(cmd.Flags(), "topic")
	cobra.MarkFlagRequired(cmd.Flags(), "partition")
	cobra.MarkFlagRequired(cmd.Flags(), "start-offset")
	return cmd
}
