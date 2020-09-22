import os
import subprocess
 
def import_all_ocp_objects(working_path,namespace):
  #Create Project/Namespace First
  for item in os.listdir(working_path):
    if os.path.isfile(item):
      os.system('oc process -f ' + item + '| oc create -f - -n ' + namespace )

  #Create OCP objects after creating namespace
  for item in os.listdir(working_path):
    if os.path.isdir(item):
      for objects in os.listdir(working_path+"/"+item):
        print(objects)
        os.system('oc process -f ' + working_path+item+"/"+objects + ' | oc create -f - -n ' + namespace )


if __name__ =="__main__":
  path="/home/ec2-user/ocp_project_backup/projects/"
  print("The default project directory to restore from is " + path + "\n")

  option=raw_input("Do you want to change the directory to restore from? Press '1' to Change, Press 'Enter' to continue using default directory: \n")
  if option == '1':
    path=raw_input("Enter the full path to directory of project (Example: /home/ec2-user/projects/: ")
  else:
    pass
  
  print("---------------List of Namespaces---------------")
  for item in os.listdir(path):
    print(item)
  print("----------End of Namespaces---------------")

  ProjectToDeploy = raw_input("Which namespace do you want to redeploy?: ")
  
  
  project_path= path + ProjectToDeploy + "/"
  
  print("\nBacking up project from " + project_path)

  #Set working project directory 
  os.chdir(project_path)

  #Import all OCP objects in project directory 
  import_all_ocp_objects(project_path,ProjectToDeploy)
