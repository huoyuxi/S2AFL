#!/bin/bash

# 如果 KEY 环境变量未设置，则赋一个默认值（可以是任意字符串）
KEY=${KEY:-"default_openai_key"}

# 更新 OpenAI Key
for x in S2AFL S2AFL-S1 S2AFL-S2;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# 复制不同版本的 S2AFL 到基准目录
for subject in ./benchmark/subjects/*/*; do
  rm -r $subject/aflnet 2>&1 >/dev/null
  cp -r aflnet $subject/aflnet

  rm -r $subject/s2afl 2>&1 >/dev/null
  cp -r S2AFL $subject/s2afl
  
  rm -r $subject/s2afl-s1 2>&1 >/dev/null
  cp -r S2AFL-S1 $subject/s2afl-s1
  
  rm -r $subject/s2afl-s2 2>&1 >/dev/null
  cp -r S2AFL-S2 $subject/s2afl-s2
done

# 构建 Docker 镜像
PFBENCH="$PWD/benchmark"
cd "$PFBENCH"
"$PFBENCH/scripts/execution/profuzzbench_build_all.sh"