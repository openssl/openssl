pipeline {
  agent any
  stages {
    stage('asdf') {
      steps {
        retry(count: 8) {
          sh 'echo 789'
        }
        
      }
    }
  }
  environment {
    abc = '123'
    tctc = 'tfctfc'
  }
}