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
	"sort"
	"time"

	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/config"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/kafka"
	"github.com/redpanda-data/redpanda/src/go/rpk/pkg/out"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/twmb/franz-go/pkg/kadm"
	"golang.org/x/exp/maps"
)

func newFindHangingCommand(fs afero.Fs, p *config.Params) *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "find-hanging",
		Short: "Find hanging transactions",
		Long: `Find hanging transactions.

This command attempts to find all transactions that are "hanging". A hanging
transaction is one that has been open for a long time with no progress being
made: no records are being produced, the transaction is just in the open state.
The --max-transaction-timeout flag controls how long a transaction can be open
with no progress before it is considered hanging. If no transactions are
hanging, this will output a few headers with no rows.
`,

		Run: func(cmd *cobra.Command, txnIDs []string) {
			p, err := p.LoadVirtualProfile(fs)
			out.MaybeDie(err, "unable to load config: %v", err)

			adm, err := kafka.NewAdmin(fs, p)
			out.MaybeDie(err, "unable to initialize kafka client: %v", err)
			defer adm.Close()

			producers, err := adm.DescribeProducers(cmd.Context(), nil)
			out.HandleShardError("DescribeProducers", err)

			// All producers that have a start offset and the last
			// timestamp is older than we want are candidates for
			// hanging.
			now := time.Now()
			candidates := make(map[int64][]kadm.DescribedProducer)
			producers.EachProducer(func(p kadm.DescribedProducer) {
				if p.CurrentTxnStartOffset == -1 {
					return
				}
				if now.Sub(time.UnixMilli(p.LastTimestamp)) < timeout {
					return
				}
				candidates[p.ProducerID] = append(candidates[p.ProducerID], p)
			})

			tw := out.NewTable(
				"topic",
				"partition",
				"producer-id",
				"producer-epoch",
				"coordinator-epoch",
				"current-txn-start-offset",
				"last-timestamp",
			)
			defer tw.Flush()

			if len(candidates) == 0 {
				return
			}

			// Now we list and describe transactions, mapping the
			// pid to the transaction.
			list, err := adm.ListTransactions(cmd.Context(), maps.Keys(candidates), nil)
			out.HandleShardError("ListTransactions", err)
			listByPID := make(map[int64]kadm.ListedTransaction)
			list.Each(func(t kadm.ListedTransaction) {
				listByPID[t.ProducerID] = t
			})
			described, err := adm.DescribeTransactions(cmd.Context(), list.TransactionalIDs()...)
			out.HandleShardError("DescribeTransactions", err)

			// Finally, over all candidates, we consider a
			// transaction hanging if:
			//
			// 1) The txn ID is missing for the PID
			//
			// 2) We are unable to describe the txn ID (we
			// pessimistically assume it is hanging)
			//
			// 3) The partition is not in the described
			// transaction.
			//
			// For (3), if a partition is returned in a described
			// transaction, we can expect the broker to eventually
			// write a txn marker and close the transaction.
			var hanging []kadm.DescribedProducer
			for pid, producingTo := range candidates {
				listed, ok := listByPID[pid]
				if !ok {
					hanging = append(hanging, producingTo...) // 1)
					continue
				}
				desc, ok := described[listed.TxnID]
				if !ok {
					hanging = append(hanging, producingTo...) // 2)
					continue
				}
				for _, to := range producingTo {
					if !desc.Topics.Lookup(to.Topic, to.Partition) {
						hanging = append(hanging, to) // 3)
					}
				}
			}

			// Now that we have everything hanging, we sort it all
			// and print.
			sort.Slice(hanging, func(i, j int) bool {
				l, r := &hanging[i], &hanging[j]
				return l.Less(r)
			})

			for _, h := range hanging {
				tw.PrintStructFields(struct {
					Topic                 string
					Partition             int32
					ProducerID            int64
					ProducerEpoch         int16
					CoordinatorEpoch      int32
					CurrentTxnStartOffset int64
					LastTimestamp         string
				}{
					h.Topic,
					h.Partition,
					h.ProducerID,
					h.ProducerEpoch,
					h.CoordinatorEpoch,
					h.CurrentTxnStartOffset,
					time.UnixMilli(h.CurrentTxnStartOffset).Format(rfc3339Milli),
				})
			}
		},
	}
	cmd.Flags().DurationVar(&timeout, "max-transaction-timeout", 10*time.Minute, "Duration after which a transaction is considered a candidate for hanging")
	return cmd
}
