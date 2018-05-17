
node('linux') {
    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '30', artifactNumToKeepStr: '10', daysToKeepStr: '30', numToKeepStr: '10')
    }
    deleteDir()

    try {

        stage('clone') {
            checkout scm
        }

        stage('build') {
            sh "mkdir -p build && cd build && cmake .. && make -j"
        }

        stage('unit_test') {
            sh "./build/unit_test"
        }
        
    } catch (err) {
        currentBuild.result = 'FAILED'
        throw err
    }
}

