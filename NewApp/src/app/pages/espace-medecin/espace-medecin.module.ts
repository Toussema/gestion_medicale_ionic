import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { EspaceMedecinPageRoutingModule } from './espace-medecin-routing.module';

import { EspaceMedecinPage } from './espace-medecin.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    EspaceMedecinPageRoutingModule
  ],
  declarations: [EspaceMedecinPage]
})
export class EspaceMedecinPageModule {}
