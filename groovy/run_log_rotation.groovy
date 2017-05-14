//michaeldkfowler
import jenkins.model.*
Jenkins.instance.getAllItems(Job.class)
.findAll { it.logRotator }
    .each {
      it.logRotator.perform(it)
    }
