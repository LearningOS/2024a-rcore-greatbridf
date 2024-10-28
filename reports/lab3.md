# 总结实现功能
向`MemorySet`中加入了函数用于检测给定地址区间是否已经映射且权限对应。并加入helper用于检测当前进程的。

实现了sys_set_priority和sys_spawn。

向原有就绪队列中加入了stride算法。

为translated_byte_array函数加入helper用于更方便地向中写入数据。

将前两次lab中的内容适配过来

# 实际情况是轮到 p1 执行吗？为什么？

**不是**，因为`u8`的范围是$0-255$，$250+10=260$，溢出后得$4$，这个时候因为$4 \lt 255$，所以还是`p2`执行。

# 简单说明为什么`STRIDE_MAX`$-$`STRIDE_MIN`$\le$`BigStride`$/2$

反证，如果`STRIDE_MAX`$-$`STRIDE_MIN`$\gt$`BigStride`$/2$，因为优先级最小就是2，所以所有进程的`pass`应该都比`BigStride`$/2$要小于等于。

但是因为现在的`STRIDE_MAX`所在的进程比这个`STRIDE_MIN`所在的进程的`stride`要大了超过二分之一，所以他在加上`pass`之前一定还比min的要大。但是这样的话，上一次一定不应该选这个`STRIDE_MAX`所在的进程，因为还有更小的（当前的`STRIDE_MIN`所在的进程）。 这样就和我们规定的每次选择`stride`最小的进程执行的规则相违背了。所以不可能出现这种情况。

# 实现`PartialOrd`

``` rust
use core::cmp::Ordering;

struct Stride(u64);

impl PartialOrd for Stride {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        const BIG_STRIDE: u64 = 1_000_000_007;

        let greater = max(self.0, other.0);
        let lesser = min(self.0, other.0);

        if greater - lesser <= BIG_STRIDE / 2 {
            self.0.partial_cmp(&other.0)
        } else {
            other.0.partial_cmp(&self.0)
        }
    }
}

impl PartialEq for Stride {
    fn eq(&self, other: &Self) -> bool {
        false
    }
}
```

# 荣誉准则

1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：

无

2. 此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：

无

3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。
