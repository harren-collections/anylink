package cron

import (
	"time"

	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/sessdata"
	"github.com/go-co-op/gocron/v2"
)

func Start() {
	// s.Cron("0 * * * *").Do(ClearAudit)
	// s.Cron("0 * * * *").Do(ClearStatsInfo)
	// s.Cron("0 * * * *").Do(ClearUserActLog)
	// s.Every(1).Day().At("00:00").Do(sessdata.CloseUserLimittimeSession)
	// s.Every(1).Day().At("00:00").Do(dbdata.ReNewCert)
	// s.Every(1).Day().At("00:00").Do(dbdata.SyncLdapUsers)
	// s.StartAsync()

	s, _ := gocron.NewScheduler(gocron.WithLocation(time.Local))

	// 每小时执行: ClearAudit, ClearStatsInfo, ClearUserActLog
	_, _ = s.NewJob(
		gocron.CronJob("0 * * * *", false),
		gocron.NewTask(ClearAudit),
	)
	_, _ = s.NewJob(
		gocron.CronJob("0 * * * *", false),
		gocron.NewTask(ClearStatsInfo),
	)
	_, _ = s.NewJob(
		gocron.CronJob("0 * * * *", false),
		gocron.NewTask(ClearUserActLog),
	)

	// 每天凌晨00:00执行的任务
	_, _ = s.NewJob(
		gocron.CronJob("0 0 * * *", false),
		gocron.NewTask(sessdata.CloseUserLimittimeSession),
	)
	_, _ = s.NewJob(
		gocron.CronJob("0 0 * * *", false),
		gocron.NewTask(dbdata.ReNewCert),
	)
	_, _ = s.NewJob(
		gocron.CronJob("0 0 * * *", false),
		gocron.NewTask(dbdata.SyncLdapUsers),
	)
	s.Start()
}
