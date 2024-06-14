use core::fmt;

/// 对于Linux服务器使用小端字节序
/// 以太网使用大端字节序，需要交换字节才能变成网络字节，同样的从网络需要
pub trait UnsignedInteger: Sized + fmt::Debug + Clone + Copy + Default {   
    fn swap(self) -> Self;    
}

impl UnsignedInteger for u16 {
    fn swap(self) -> Self {
        self.swap_bytes()
    }
}

impl UnsignedInteger for u32 {
    fn swap(self) -> Self {
        self.swap_bytes()
    }
}

impl UnsignedInteger for u64 {
    fn swap(self) -> Self {
        self.swap_bytes()
    }
}

impl UnsignedInteger for u128 {
    fn swap(self) -> Self {
        self.swap_bytes()
    }
}

/// NetEndian代表以太网中的数据包，从数据流读出来需要get会转成host 字节序。
/// 同样的写入需要set会转成netendian大端字节序。
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NetEndian<T: UnsignedInteger>(T);

impl<T: UnsignedInteger> NetEndian<T> {
    /// 从网络数据包中读取，需要从大端转成小端
    pub fn get(&self) -> T {
        self.0.swap()
    }

    /// 从内存中设置网络数据包
    pub fn set(&mut self, t: T) {
        self.0 = t.swap();
    }
}
