import jenkins.model.*
 
 
for(item in Jenkins.instance.items) {
     println("job $item.name")
     item.publishersList.replace(new  hudson.plugins.chucknorris.CordellWalkerRecorder());
}
