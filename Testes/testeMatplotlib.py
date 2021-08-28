# coding: utf-8

import numpy as np 
import matplotlib.pyplot as plt 

x = np.arange(1,6) 
dados = np.random.randint(0,50,5)

plt.style.use('ggplot')


plt.bar(x,dados)
plt.show()

