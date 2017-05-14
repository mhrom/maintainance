import hudson.model.*
 
def str_view = "MyProduct_Release_1.0"
def str_search = "Rel_1.0"
def str_replace = "Rel_1.1"
 
def view = Hudson.instance.getView(str_view)
 
//copy all projects of a view
for(item in view.getItems())
{
 
  //create the new project name
  newName = item.getName().replace(str_search, str_replace)
 
 
  // copy the job, disable and save it
  def job = Hudson.instance.copy(item, newName)
  job.disabled = true
  job.save()
  
  // update the workspace to avoid having two projects point to the same location
  AbstractProject project = job
  def new_workspace = project.getCustomWorkspace().replace(str_search, str_replace)
  project.setCustomWorkspace(new_workspace)
  project.save()
  
  println(" $item.name copied as $newName")
 
}
