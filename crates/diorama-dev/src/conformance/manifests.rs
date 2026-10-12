//! Pinned manifest tier definitions and smoke test specifications matching KubeSolo baseline.

pub const SMOKE_NAMESPACE: &str = "e2e-smoke";

pub const SMOKE_POD_YAML: &str = r#"apiVersion: v1
kind: Pod
metadata:
  name: smoke-busybox
  namespace: e2e-smoke
spec:
  containers:
    - name: busybox
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
  restartPolicy: Never
"#;

pub const TIER1_NAMESPACE: &str = "tier1-workload";

pub const TIER1_MANIFEST_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier1-workload
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: tier1-workload
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
          readinessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 2
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: web-clusterip
  namespace: tier1-workload
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web-nodeport
  namespace: tier1-workload
spec:
  type: NodePort
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
"#;

pub const TIER2_NAMESPACE: &str = "tier2-storage";

pub const TIER2_PVC_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier2-storage
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
  namespace: tier2-storage
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-path
  resources:
    requests:
      storage: 64Mi
"#;

pub const TIER2_WRITER_YAML: &str = r#"apiVersion: batch/v1
kind: Job
metadata:
  name: writer
  namespace: tier2-storage
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: writer
          image: busybox:1.36
          command: ["sh", "-c", "echo persisted-ok > /data/marker && sync"]
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: data
"#;

pub const TIER2_READER_YAML: &str = r#"apiVersion: v1
kind: Pod
metadata:
  name: reader
  namespace: tier2-storage
spec:
  restartPolicy: Never
  containers:
    - name: reader
      image: busybox:1.36
      command: ["sh", "-c", "test \"$(cat /data/marker)\" = persisted-ok && sleep 3600"]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: data
"#;

pub const TIER3_NAMESPACE: &str = "tier3-config";

pub const TIER3_CONFIG_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier3-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: tier3-config
data:
  greeting: hello-kubesolo
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: tier3-config
type: Opaque
stringData:
  token: s3cr3t-value
---
apiVersion: v1
kind: Pod
metadata:
  name: consumer
  namespace: tier3-config
spec:
  restartPolicy: Never
  containers:
    - name: consumer
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      env:
        - name: GREETING
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: greeting
      volumeMounts:
        - name: secret
          mountPath: /etc/secret
          readOnly: true
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: secret
      secret:
        secretName: app-secret
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              path: sa-token
              expirationSeconds: 3600
              audience: kubesolo-e2e
"#;

pub const TIER4_NAMESPACE: &str = "tier4-controllers";

pub const TIER4_CONTROLLERS_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier4-controllers
---
apiVersion: batch/v1
kind: Job
metadata:
  name: oneshot
  namespace: tier4-controllers
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: oneshot
          image: busybox:1.36
          command: ["sh", "-c", "echo done"]
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: periodic
  namespace: tier4-controllers
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: tick
              image: busybox:1.36
              command: ["sh", "-c", "echo tick"]
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
  namespace: tier4-controllers
spec:
  selector:
    matchLabels:
      app: agent
  template:
    metadata:
      labels:
        app: agent
    spec:
      containers:
        - name: agent
          image: busybox:1.36
          command: ["sh", "-c", "sleep 3600"]
---
apiVersion: v1
kind: Service
metadata:
  name: stateful
  namespace: tier4-controllers
spec:
  clusterIP: None
  selector:
    app: stateful
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: stateful
  namespace: tier4-controllers
spec:
  serviceName: stateful
  replicas: 1
  selector:
    matchLabels:
      app: stateful
  template:
    metadata:
      labels:
        app: stateful
    spec:
      containers:
        - name: stateful
          image: busybox:1.36
          command: ["sh", "-c", "sleep 3600"]
"#;

pub const TIER5_NAMESPACE_A: &str = "tier5-a";
pub const TIER5_NAMESPACE_B: &str = "tier5-b";

pub const TIER5_DNS_LB_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier5-a
---
apiVersion: v1
kind: Namespace
metadata:
  name: tier5-b
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: tier5-a
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: tier5-a
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web-lb
  namespace: tier5-a
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: dns-client
  namespace: tier5-b
spec:
  restartPolicy: Never
  containers:
    - name: client
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
"#;

pub const TIER6_NAMESPACE: &str = "tier6-lb";

pub const TIER6_LB_UPDATE_YAML: &str = r#"apiVersion: v1
kind: Namespace
metadata:
  name: tier6-lb
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: tier6-lb
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: flip-me
  namespace: tier6-lb
spec:
  type: ClusterIP
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: born-lb
  namespace: tier6-lb
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: 80
---
apiVersion: batch/v1
kind: Job
metadata:
  name: guard
  namespace: tier6-lb
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: work
          image: busybox:1.36
          command: ["sh", "-c", "true"]
"#;

pub const TIER6_FLIP_TO_LB_YAML: &str = r#"apiVersion: v1
kind: Service
metadata:
  name: flip-me
  namespace: tier6-lb
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - name: http
      port: 80
      targetPort: 80
    - name: edge
      port: 9000
      targetPort: 80
    - name: edge-tls
      port: 9443
      targetPort: 80
"#;
