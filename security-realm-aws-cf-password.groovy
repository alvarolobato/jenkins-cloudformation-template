// Copyright CloudBees Inc. 2015


import hudson.BulkChange
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins
import hudson.Util

import static hudson.security.AuthorizationStrategy.UNSECURED
import static hudson.security.SecurityRealm.NO_AUTHENTICATION

File awsProperties = new File(Jenkins.getInstance().getRootDir(), ".aws.init.properties")
File markerFile = new File(Jenkins.getInstance().getRootDir(), ".aws-security-configured")
String username
String password

def initUserPassword = {
    //is there is a properties file, whe prioritize it over instance ID
    if (awsProperties.exists()){
        Properties props = new Properties()
        awsProperties.withInputStream {
            props.load(it)
        }

        username=props.username
        password=props.password
        println "[aws-security-realm] Using password provided on CloudFormation template"
    }else{
        username="admin"
        password=getAWSInstanceId()
        println "[aws-security-realm] Using AWS instance ID as password"
    }
}

def getAWSInstanceId = {
    HttpURLConnection connection = (HttpURLConnection) new URL("http://169.254.169.254/latest/meta-data/instance-id").openConnection()
    int statusCode = connection.getResponseCode();
    if (statusCode != 200) {
        println "[aws-security-realm] Failed to retrieve instance ID from amazon metadata service - are you _really_ running on AWS ?"
        throw new IOException("Filed to access AWS metadata service $statusCode");
    }

    InputStream stream = null;
    try {
        stream = connection.getInputStream()
        String instanceId = new BufferedReader(new InputStreamReader(stream)).readLine()
        return instanceId;
    } finally {
        stream?.close()
    }
}


if (markerFile.exists()) {
    println "[aws-security-realm] Security already configured, skipping"
    return;
}
println "[aws-security-realm] Starting to configure Security..."

def jenkins = Jenkins.getInstance()
BulkChange bulkChange = new BulkChange(jenkins)
try {

    initUserPassword()
    
    //removed until we replace this script on the image instead of overriding the original with CF template
    //if (NO_AUTHENTICATION.equals(jenkins.getSecurityRealm())) {
        // Set security realm to User Database, with sign-up disabled.
        def realm = new HudsonPrivateSecurityRealm(false, false, null)
        realm.createAccount(username, password)
        jenkins.setSecurityRealm(realm)
    //}

    // User can do anything when logged in - including change security settings.
    if (UNSECURED.equals(jenkins.getAuthorizationStrategy())) {
        jenkins.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy())
    }

    bulkChange.commit()
    println "[aws-security-realm] Jenkins has been secured, you can login as '"+username+"'"

    //delete the file, it has plain-text password
    if (awsProperties.exists()){
        Util.deleteFile(awsProperties);
    }
} catch (UnknownHostException e) {
    bulkChange.abort()
    println "[aws-security-realm] Failed to connect to amazon metadata service. Assume Jenkins is not running on AWS, skip."
    return
} catch (Exception e) {
    bulkChange.abort()
    println "[aws-security-realm] Jenkins configuration changes aborted due to " + e
    e.printStackTrace(System.out)
} finally {
    // this script is intended to run on a "blank" jenkins configuration. Disable it even if an exception occurred
    try {
        markerFile.createNewFile()
    } catch (Exception e) {
        println "[aws-security-realm] Exception creating $markerFile :"+ e
    }
}


