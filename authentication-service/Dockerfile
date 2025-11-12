FROM maven:3.9.9 AS builder
WORKDIR /application
COPY . .
RUN --mount=type=cache,target=/root/.m2 mvn clean package -pl authentication-service -am -Dmaven.test.skip

FROM bellsoft/liberica-openjre-alpine:21-cds AS layers
WORKDIR /application
COPY --from=builder /application/authentication-service/target/*.jar app.jar
RUN java -Djarmode=layertools -jar app.jar extract --destination extracted

FROM bellsoft/liberica-openjre-alpine:21-cds
VOLUME /tmp
RUN adduser -S spring-user
USER spring-user

WORKDIR /application

COPY --from=layers /application/extracted/dependencies/ ./
COPY --from=layers /application/extracted/spring-boot-loader/ ./
COPY --from=layers /application/extracted/snapshot-dependencies/ ./
COPY --from=layers /application/extracted/application/ ./

COPY --from=layers /application/app.jar ./

RUN java -XX:ArchiveClassesAtExit=app.jsa -Dspring.context.exit=onRefresh -jar app.jar & exit 0

ENV JAVA_CDS_OPTS="-XX:SharedArchiveFile=app.jsa -Xlog:class+load:file=/tmp/classload.log"
ENV JAVA_ERROR_FILE_OPTS="-XX:ErrorFile=/tmp/java_error.log"
ENV JAVA_HEAP_DUMP_OPTS="-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp"
ENV JAVA_ON_OUT_OF_MEMORY_OPTS="-XX:+ExitOnOutOfMemoryError"
ENV JAVA_NATIVE_MEMORY_TRACKING_OPTS="-XX:NativeMemoryTracking=summary -XX:+UnlockDiagnosticVMOptions -XX:+PrintNMTStatistics"

ENTRYPOINT java \
    $JAVA_HEAP_DUMP_OPTS \
    $JAVA_ON_OUT_OF_MEMORY_OPTS \
    $JAVA_ERROR_FILE_OPTS \
    $JAVA_NATIVE_MEMORY_TRACKING_OPTS \
    $JAVA_CDS_OPTS \
    -jar app.jar
