
node('linux') {
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

