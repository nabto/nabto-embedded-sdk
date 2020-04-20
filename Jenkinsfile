
pipeline {
    agent none
    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    stages {
        stage('Build') {
            parallel {
                stage('Build linux amd64') {
                    agent {
                        dockerfile {
                            filename 'linux64.dockerfile'
                            dir 'build/linux'
                        }
                    }
                    environment {
                        releaseDir = "linux-release"
                        srcDir = pwd()
                    }

                    steps {
                        checkout scm
                        dir('build-amd64') {
                            sh "cmake -DCMAKE_INSTALL_PREFIX=${WORKSPACE}/${releaseDir} -DCMAKE_BUILD_TYPE=Release ${srcDir}/superbuild"
                            sh "cmake --build ."
                        }
                        stash name: "${releaseDir}", includes: "build-amd64/nabto-embedded-sdk/**"
                    }
                }
                stage('Build linux armhf') {
                    agent {
                        dockerfile {
                            filename 'armhf.dockerfile'
                            dir 'build/linux'
                        }
                    }
                    environment {
                        CC="arm-linux-gnueabihf-gcc-8"
                        CXX="arm-linux-gnueabihf-g++-8"
                        releaseDir = "linux-armhf-release"
                        srcDir = pwd()

                    }
                    steps {
                        checkout scm
                        dir('build-armhf') {
                            sh "cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$WORKSPACE/${releaseDir} ${srcDir}/superbuild"
                            sh "cmake --build ."
                        }
                        stash name: "${releaseDir}", includes: "build-armhf/nabto-embedded-sdk/**"
                    }
                }
                stage('Build on mac') {
                    agent {
                        label "mac"
                    }
                    environment {
                        PATH = "/usr/local/bin:$PATH"
                        releaseDir = "mac-release"
                        srcDir = pwd()
                    }
                    steps {
                        checkout scm
                        dir('build-mac') {
                            sh "cmake -DCMAKE_INSTALL_PREFIX=${WORKSPACE}/${releaseDir} -DCMAKE_BUILD_TYPE=Release ${srcDir}/superbuild"
                            sh "cmake --build ."
                        }
                        stash name: "${releaseDir}", includes: "build-mac/nabto-embedded-sdk/**"
                    }
                }
            }
        }
        stage('Test') {
            parallel {
                stage('Test on linux') {
                    agent {
                        dockerfile {
                            filename 'linux64.dockerfile'
                            dir 'build/linux'
                        }
                    }
                    steps {
                        dir ('test-dir') {
                            unstash "linux-release"
                            sh "./build-amd64/nabto-embedded-sdk/bin/embedded_unit_test --log_format=JUNIT --log_sink=embedded_unit_test_linux.xml"
                        }
                    }
                    post {
                        always {
                            junit "test-dir/*.xml"
                        }
                    }
                }
                stage('Test on mac') {
                    agent {
                        label "mac"
                    }
                    steps {
                        dir ('test-dir') {
                            unstash "mac-release"
                            sh "./build-mac/nabto-embedded-sdk/bin/embedded_unit_test --log_format=JUNIT --log_sink=embedded_unit_test_mac.xml"
                        }
                    }
                    post {
                        always {
                            junit "test-dir/*.xml"
                        }
                    }
                }
            }
        }
        stage('Deploy') {
        // TODO
            agent {
                label "linux"
            }
            steps {
                dir('files') {
                    unstash "linux-release"
                    unstash "linux-armhf-release"
                    unstash "mac-release"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'files/**', onlyIfSuccessful: true
                }
            }
        }
    }
}
