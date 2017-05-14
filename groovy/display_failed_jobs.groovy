// Get the list of failed jobs
activeJobs = hudson.model.Hudson.instance.items.findAll{job -> job.isBuildable()}
failedRuns = activeJobs.findAll{job -> job.lastBuild != null && job.lastBuild.result == hudson.model.Result.FAILURE}
// Do something with them - e.g. listing them
failedRuns.each{run -> println(run.name)}
